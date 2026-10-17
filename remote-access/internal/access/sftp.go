package access

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func validRemoteRoot(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\\\x00\r\n") && path.Clean(p) == p && len(p) <= 2048
}
func safeRelative(p string) bool {
	if p == "" || len(p) > 2048 || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00:\r\n") {
		return false
	}
	for _, x := range strings.Split(p, "/") {
		if x == "" || x == "." || x == ".." {
			return false
		}
	}
	return true
}
func within(p, root string) bool {
	return p == root || root == "/" && strings.HasPrefix(p, "/") || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}
func withinAny(p string, roots []string) bool {
	for _, r := range roots {
		if within(p, r) {
			return true
		}
	}
	return false
}

type FileConn struct {
	SSH        *ssh.Client
	SFTP       *sftp.Client
	Account    Account
	Policy     Policy
	stop       func() bool
	MkdirRoots []string
	release    func()
}

func (f *FileConn) Close() {
	if f.release != nil {
		f.release()
	}
	if f.stop != nil {
		f.stop()
	}
	f.SFTP.Close()
	f.SSH.Close()
}
func (a *App) fileConn(ctx context.Context, u *User, accountID, action string) (*FileConn, error) {
	release, e := a.reserveFiles(u, accountID)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	x, e := a.account(ctx, u, accountID)
	if e != nil {
		return nil, e
	}
	p, e := a.policy(ctx, u, x, "sftp", action)
	if e != nil {
		return nil, e
	}
	ep, e := a.endpoint(ctx, u, x.Asset, "sftp")
	if e != nil {
		return nil, e
	}
	client, e := a.dialSSH(ctx, u, x, ep)
	if e != nil {
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { client.Close() })
	sc, e := sftp.NewClient(client, sftp.MaxPacket(32768), sftp.MaxConcurrentRequestsPerFile(8))
	if e != nil {
		client.Close()
		return nil, fail(502, "sftp_unavailable", "目标未开放 SFTP 子系统")
	}
	mkdirRoots := []string{}
	if mp, err := a.policy(ctx, u, x, "sftp", "sftp.mkdir"); err == nil {
		mkdirRoots = mp.Limits.WriteRoots
	}
	monitorCtx, monitorCancel := context.WithCancel(ctx)
	go func() {
		tick := time.NewTicker(time.Duration(a.Config.RevokePoll) * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-monitorCtx.Done():
				return
			case <-tick.C:
				checkCtx, cancel := context.WithTimeout(monitorCtx, 3*time.Second)
				valid := a.validLogin(checkCtx, u)
				if a.leaseLost.Load() {
					valid = errors.New("gateway lease lost")
				}
				current, err := a.account(checkCtx, u, x.ID)
				if valid == nil && err == nil && current.CredentialVersion == x.CredentialVersion {
					policy, er := a.policy(checkCtx, u, current, "sftp", action)
					if er != nil || policy.Version != p.Version {
						valid = errors.New("authorization changed")
					}
				} else {
					valid = errors.New("session changed")
				}
				cancel()
				if valid != nil {
					client.Close()
					return
				}
			}
		}
	}()
	success = true
	return &FileConn{release: release, SSH: client, SFTP: sc, Account: x, Policy: p, MkdirRoots: mkdirRoots, stop: func() bool { monitorCancel(); return stop() }}, nil
}
func (f *FileConn) resolve(p string, write, newPath bool) (string, error) {
	roots := f.Policy.Limits.ReadRoots
	if write {
		roots = f.Policy.Limits.WriteRoots
	}
	if !validRemoteRoot(p) || !withinAny(p, roots) {
		return "", fail(403, "path_denied", "路径不在允许目录内")
	}
	realRoots := []string{}
	for _, r := range roots {
		rp, e := f.SFTP.RealPath(r)
		if e == nil {
			realRoots = append(realRoots, path.Clean(rp))
		}
	}
	if len(realRoots) == 0 {
		return "", fail(403, "root_unavailable", "允许根目录不存在或无权访问")
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	current := "/"
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = path.Join(current, part)
		info, e := f.SFTP.Lstat(current)
		if e != nil {
			if newPath && os.IsNotExist(e) && i == len(parts)-1 {
				parent, e := f.SFTP.RealPath(path.Dir(current))
				if e != nil || !withinAny(path.Clean(parent), realRoots) {
					return "", fail(403, "parent_denied", "目标父目录不在允许范围内")
				}
				return path.Join(parent, part), nil
			}
			return "", fail(404, "remote_path_unavailable", "远程路径不存在或不可访问")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fail(403, "symlink_denied", "默认不跟随符号链接")
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return "", fail(403, "special_file_denied", "不允许操作特殊文件")
		}
	}
	real, e := f.SFTP.RealPath(p)
	if e != nil || !withinAny(path.Clean(real), realRoots) {
		return "", fail(403, "realpath_denied", "实际路径越出允许目录")
	}
	return path.Clean(real), nil
}
func (a *App) entries(w http.ResponseWriter, r *http.Request, u *User) error {
	f, e := a.fileConn(r.Context(), u, r.URL.Query().Get("accountId"), "sftp.list")
	if e != nil {
		return e
	}
	defer f.Close()
	p := r.URL.Query().Get("path")
	if p == "" {
		if len(f.Policy.Limits.ReadRoots) == 0 {
			return fail(403, "no_read_root", "未配置读取目录")
		}
		p = f.Policy.Limits.ReadRoots[0]
	}
	p, e = f.resolve(p, false, false)
	if e != nil {
		return e
	}
	files, e := f.SFTP.ReadDir(p)
	if e != nil {
		return fail(502, "sftp_list_failed", "目录无法读取")
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].IsDir() != files[j].IsDir() {
			return files[i].IsDir()
		}
		return files[i].Name() < files[j].Name()
	})
	items := []map[string]any{}
	for _, fi := range files {
		items = append(items, map[string]any{"name": fi.Name(), "directory": fi.IsDir(), "symlink": fi.Mode()&os.ModeSymlink != 0, "size": fi.Size(), "modified": fi.ModTime(), "mode": fi.Mode().String()})
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if start < 0 {
		start = 0
	}
	end := min(start+200, len(items))
	if start > len(items) {
		start = len(items)
	}
	jsonOut(w, 200, map[string]any{"path": p, "entries": items[start:end], "total": len(items), "nextOffset": end, "accountId": f.Account.ID, "assetId": f.Account.Asset, "readRoots": f.Policy.Limits.ReadRoots, "writeRoots": f.Policy.Limits.WriteRoots})
	return nil
}
func (a *App) fileOperation(w http.ResponseWriter, r *http.Request, u *User) error {
	var in struct {
		Account     string `json:"accountId"`
		Path        string `json:"path"`
		Destination string `json:"destination"`
		Recursive   bool   `json:"recursive"`
		Confirm     bool   `json:"confirm"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	action := "sftp." + path.Base(r.URL.Path)
	if action == "sftp.directories" {
		action = "sftp.mkdir"
	}
	f, e := a.fileConn(r.Context(), u, in.Account, action)
	if e != nil {
		return e
	}
	defer f.Close()
	p, e := f.resolve(in.Path, true, action == "sftp.mkdir")
	if e != nil {
		return e
	}
	switch action {
	case "sftp.mkdir":
		e = f.SFTP.Mkdir(p)
	case "sftp.rename":
		var dest string
		dest, e = f.resolve(in.Destination, true, true)
		if e == nil {
			if _, err := f.SFTP.Lstat(dest); err == nil {
				return fail(409, "name_conflict", "目标名称已存在")
			}
			e = f.SFTP.Rename(p, dest)
		}
	case "sftp.delete":
		if !in.Confirm {
			return fail(409, "confirmation_required", "删除需要明确确认")
		}
		for _, root := range f.Policy.Limits.WriteRoots {
			if p == root {
				return fail(403, "root_delete_denied", "不能删除授权根目录")
			}
		}
		var info os.FileInfo
		info, e = f.SFTP.Lstat(p)
		if e != nil {
			break
		}
		if info.IsDir() {
			if in.Recursive {
				e = a.removeTree(r.Context(), u, f, p, 0, new(int))
			} else {
				e = f.SFTP.RemoveDirectory(p)
			}
		} else {
			e = f.SFTP.Remove(p)
		}
	default:
		return fail(404, "operation_unknown", "操作不存在")
	}
	if e != nil {
		_ = a.audit(r.Context(), u, action, f.Account.ID, "failed", "", map[string]string{"path": p})
		return fail(502, "file_operation_failed", "远程文件操作失败，可能已部分执行")
	}
	if e = a.audit(r.Context(), u, action, f.Account.ID, "success", "", map[string]string{"path": p}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) removeTree(ctx context.Context, u *User, f *FileConn, p string, depth int, count *int) error {
	if depth > f.Policy.Limits.MaxDepth {
		return errors.New("depth limit")
	}
	if e := a.validLogin(ctx, u); e != nil {
		return e
	}
	if _, e := a.policy(ctx, u, f.Account, "sftp", "sftp.delete"); e != nil {
		return e
	}
	p, e := f.resolve(p, true, false)
	if e != nil {
		return e
	}
	entries, e := f.SFTP.ReadDir(p)
	if e != nil {
		return e
	}
	for _, fi := range entries {
		*count++
		if *count > f.Policy.Limits.MaxFiles {
			return errors.New("file count limit")
		}
		child := path.Join(p, fi.Name())
		if fi.Mode()&os.ModeSymlink != 0 || (!fi.IsDir() && !fi.Mode().IsRegular()) {
			return errors.New("special file refused")
		}
		if fi.IsDir() {
			e = a.removeTree(ctx, u, f, child, depth+1, count)
		} else {
			_, e = f.resolve(child, true, false)
			if e == nil {
				e = f.SFTP.Remove(child)
			}
		}
		if e != nil {
			return e
		}
	}
	return f.SFTP.RemoveDirectory(p)
}

type Transfer struct {
	ID, Workspace, User, LoginHash, Asset, Account, Gateway, Direction, State, Target, Conflict, Policy string
	Credential                                                                                          int64
	Total, Done                                                                                         int64
	Expires                                                                                             time.Time
}
type ManifestItem struct {
	Path      string `json:"path"`
	Directory bool   `json:"directory"`
	Size      int64  `json:"size"`
	Modified  int64  `json:"modifiedMs"`
	SHA       string `json:"sha256"`
}

func (a *App) task(ctx context.Context, u *User, id string) (Transfer, error) {
	var t Transfer
	e := a.store(ctx).QueryRow(ctx, "SELECT id,workspace,user_id,login_id_hash,asset_id,account_id,gateway_id,direction,state,target_path,conflict,policy_version,credential_version,total_bytes,done_bytes,expires_at FROM ra_transfers WHERE workspace=$1 AND user_id=$2 AND id=$3", u.Workspace, u.ID, id).Scan(&t.ID, &t.Workspace, &t.User, &t.LoginHash, &t.Asset, &t.Account, &t.Gateway, &t.Direction, &t.State, &t.Target, &t.Conflict, &t.Policy, &t.Credential, &t.Total, &t.Done, &t.Expires)
	if e != nil {
		return t, fail(404, "task_not_found", "任务不存在或无权访问")
	}
	if t.Gateway != a.Config.GatewayID {
		return t, gatewayError(t.Gateway)
	}
	if time.Now().After(t.Expires) {
		return t, fail(410, "task_expired", "任务已过期")
	}
	if e = a.validLogin(ctx, u); e != nil {
		return t, e
	}
	original := *u
	original.LoginHash = t.LoginHash
	if e = a.validLogin(ctx, &original); e != nil {
		return t, e
	}
	x, e := a.account(ctx, u, t.Account)
	if e != nil {
		return t, e
	}
	if x.CredentialVersion != t.Credential {
		return t, fail(410, "credential_changed", "凭据版本已变更")
	}
	p, e := a.policy(ctx, u, x, "sftp", "sftp."+t.Direction)
	if e != nil {
		return t, e
	}
	if p.Version != t.Policy {
		return t, fail(410, "policy_changed", "任务授权已变化，请重新创建任务")
	}
	return t, nil
}
func (a *App) taskLock(id string) *sync.Mutex {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.transferLocks[id] == nil {
		a.transferLocks[id] = new(sync.Mutex)
	}
	return a.transferLocks[id]
}
func (a *App) transfers(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	if r.Method == "GET" {
		if id := r.PathValue("id"); id != "" {
			t, e := a.task(ctx, u, id)
			if e != nil {
				return e
			}
			items, e := a.list(ctx, "SELECT i.id,relative_path,is_directory,i.size,modified_ms,i.sha256,i.offset_bytes,state,retries,error_code,COALESCE((SELECT json_agg(json_build_object('offset',c.offset_bytes,'size',c.size,'sha256',c.sha256) ORDER BY c.offset_bytes) FROM ra_transfer_chunks c WHERE c.item_id=i.id),'[]') AS chunks FROM ra_transfer_items i WHERE task_id=$1 ORDER BY relative_path LIMIT 10000", id)
			if e != nil {
				return e
			}
			jsonOut(w, 200, map[string]any{"id": t.ID, "direction": t.Direction, "state": t.State, "assetId": t.Asset, "accountId": t.Account, "totalBytes": t.Total, "doneBytes": t.Done, "items": items})
			return nil
		}
		v, e := a.list(ctx, "SELECT id,asset_id,account_id,direction,state,target_path,total_bytes,done_bytes,error_code,created_at,updated_at FROM ra_transfers WHERE workspace=$1 AND user_id=$2 AND NOT hidden_from_list ORDER BY created_at DESC LIMIT 200", u.Workspace, u.ID)
		if e != nil {
			return e
		}
		jsonOut(w, 200, v)
		return nil
	}
	var in struct {
		Account          string   `json:"accountId"`
		Direction        string   `json:"direction"`
		Target           string   `json:"target"`
		Conflict         string   `json:"conflict"`
		ConfirmOverwrite bool     `json:"confirmOverwrite"`
		Paths            []string `json:"paths"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !contains([]string{"upload", "download"}, in.Direction) || !contains([]string{"ask", "skip", "rename", "overwrite"}, in.Conflict) {
		return fail(400, "transfer_invalid", "任务方向或冲突策略无效")
	}
	if in.Direction == "download" {
		if len(in.Paths) == 0 || len(in.Paths) > 1000 {
			return fail(400, "download_paths", "请选择文件或目录")
		}
		seen := map[string]bool{}
		for _, p := range in.Paths {
			if !safeRelative(p) || seen[p] {
				return fail(400, "download_path", "路径无效或重复")
			}
			seen[p] = true
		}
	}
	f, e := a.fileConn(ctx, u, in.Account, "sftp."+in.Direction)
	if e != nil {
		return e
	}
	defer f.Close()
	if in.Conflict == "overwrite" && (!f.Policy.Limits.AllowOverwrite || !in.ConfirmOverwrite) {
		return fail(403, "overwrite_denied", "覆盖需要权限和明确确认")
	}
	target, e := f.resolve(in.Target, in.Direction == "upload", false)
	if e != nil {
		return e
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT id FROM ra_users WHERE id=$1 FOR UPDATE", u.ID); e != nil {
		return e
	}
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM ra_transfers WHERE user_id=$1 AND state IN('queued','scanning','running','paused') AND expires_at>now()", u.ID).Scan(&n); e != nil {
		return e
	}
	if n >= min(a.Config.MaxTransfers, f.Policy.Limits.MaxConcurrent) {
		return fail(429, "transfer_quota", "传输任务数量达到上限")
	}
	id := ID()
	_, e = tx.Exec(ctx, "INSERT INTO ra_transfers(id,workspace,user_id,login_id_hash,asset_id,account_id,gateway_id,direction,state,target_path,conflict,policy_version,credential_version,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'scanning',$9,$10,$11,$12,$13)", id, u.Workspace, u.ID, u.LoginHash, f.Account.Asset, f.Account.ID, a.Config.GatewayID, in.Direction, target, in.Conflict, f.Policy.Version, f.Account.CredentialVersion, time.Now().Add(24*time.Hour))
	if e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	if in.Direction == "download" {
		if len(in.Paths) == 0 || len(in.Paths) > 1000 {
			return fail(400, "download_paths", "请选择要下载的文件或目录")
		}
		manifest := []ManifestItem{}
		seen := map[string]bool{}
		var total int64
		for _, p := range in.Paths {
			if !safeRelative(p) || seen[p] {
				return fail(400, "download_path", "路径无效或重复")
			}
			seen[p] = true
			if e = a.scanDownload(ctx, u, f, path.Join(target, p), p, 0, &manifest, &total); e != nil {
				_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state='failed',error_code='scan_failed' WHERE id=$1", id)
				return e
			}
		}
		for i := 0; i < len(manifest); i += 500 {
			if e = a.insertItems(ctx, id, manifest[i:min(i+500, len(manifest))], f.Policy.Limits); e != nil {
				_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state='failed',error_code='manifest_failed' WHERE id=$1", id)
				return e
			}
		}
		_, e = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state='queued' WHERE id=$1", id)
		if e != nil {
			return e
		}
	}
	if e = a.audit(ctx, u, "transfer.create", f.Account.ID, "success", id, map[string]any{"direction": in.Direction}); e != nil {
		return e
	}
	jsonOut(w, 201, map[string]string{"id": id, "state": map[bool]string{true: "queued", false: "scanning"}[in.Direction == "download"]})
	return nil
}
func (a *App) scanDownload(ctx context.Context, u *User, f *FileConn, full, relative string, depth int, items *[]ManifestItem, total *int64) error {
	if depth > f.Policy.Limits.MaxDepth || len(*items) >= f.Policy.Limits.MaxFiles {
		return fail(413, "manifest_limit", "目录深度或文件数量超过上限")
	}
	if e := a.validLogin(ctx, u); e != nil {
		return e
	}
	if _, e := a.policy(ctx, u, f.Account, "sftp", "sftp.download"); e != nil {
		return e
	}
	p, e := f.resolve(full, false, false)
	if e != nil {
		return e
	}
	fi, e := f.SFTP.Lstat(p)
	if e != nil {
		return fail(502, "file_changed", "扫描时文件不可用")
	}
	item := ManifestItem{Path: relative, Directory: fi.IsDir(), Modified: fi.ModTime().UnixMilli()}
	if !fi.IsDir() {
		item.Size = fi.Size()
		*total += fi.Size()
		if fi.Size() > f.Policy.Limits.MaxFileBytes || *total > f.Policy.Limits.MaxTotalBytes {
			return fail(413, "size_limit", "下载超过大小限制")
		}
	}
	*items = append(*items, item)
	if fi.IsDir() {
		entries, e := f.SFTP.ReadDir(p)
		if e != nil {
			return e
		}
		for _, child := range entries {
			if !safeRelative(child.Name()) {
				return fail(400, "filename_invalid", "目标文件名不能安全打包")
			}
			if e = a.scanDownload(ctx, u, f, path.Join(p, child.Name()), path.Join(relative, child.Name()), depth+1, items, total); e != nil {
				return e
			}
		}
	}
	return nil
}
func (a *App) insertItems(ctx context.Context, id string, items []ManifestItem, l Limits) error {
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var total int64
	var state string
	if e = tx.QueryRow(ctx, "SELECT total_bytes,state FROM ra_transfers WHERE id=$1 FOR UPDATE", id).Scan(&total, &state); e != nil {
		return e
	}
	if state != "scanning" {
		return fail(409, "manifest_closed", "任务清单已封存")
	}
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM ra_transfer_items WHERE task_id=$1", id).Scan(&n); e != nil {
		return e
	}
	if len(items) > 500 || n+len(items) > l.MaxFiles {
		return fail(413, "file_count_limit", "清单条目超过上限；每批最多 500 项")
	}
	for _, item := range items {
		if !safeRelative(item.Path) || strings.Count(item.Path, "/")+1 > l.MaxDepth || item.Size < 0 || item.Size > l.MaxFileBytes || item.Directory && item.Size != 0 || item.SHA != "" && !shaPattern.MatchString(item.SHA) {
			return fail(400, "manifest_invalid", "清单路径、摘要或大小无效")
		}
		total += item.Size
		if total > l.MaxTotalBytes {
			return fail(413, "task_size_limit", "任务总大小超过限制")
		}
		if _, e = tx.Exec(ctx, "INSERT INTO ra_transfer_items(id,task_id,relative_path,is_directory,size,modified_ms,sha256) VALUES($1,$2,$3,$4,$5,$6,$7)", ID(), id, item.Path, item.Directory, item.Size, item.Modified, item.SHA); e != nil {
			return fail(409, "manifest_conflict", "存在重复路径或清单冲突")
		}
	}
	if _, e = tx.Exec(ctx, "UPDATE ra_transfers SET total_bytes=$1,updated_at=now() WHERE id=$2", total, id); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (a *App) manifest(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	t, e := a.task(ctx, u, r.PathValue("id"))
	if e != nil {
		return e
	}
	if t.Direction != "upload" {
		return fail(409, "upload_required", "仅上传任务接受清单")
	}
	var in struct {
		Items []ManifestItem `json:"items"`
		Final bool           `json:"final"`
	}
	if e = decode(w, r, &in); e != nil {
		return e
	}
	x, e := a.account(ctx, u, t.Account)
	if e != nil {
		return e
	}
	p, e := a.policy(ctx, u, x, "sftp", "sftp.upload")
	if e != nil {
		return e
	}
	if e = a.insertItems(ctx, t.ID, in.Items, p.Limits); e != nil {
		return e
	}
	if in.Final {
		_, e = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state='queued',updated_at=now() WHERE id=$1 AND state='scanning'", t.ID)
		if e != nil {
			return e
		}
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) mkdirParents(f *FileConn, base, relative string) error {
	current := base
	for _, part := range strings.Split(relative, "/") {
		if part == "" || part == "." {
			continue
		}
		current = path.Join(current, part)
		_, e := f.resolve(current, true, true)
		if e != nil {
			return e
		}
		if info, err := f.SFTP.Lstat(current); err == nil {
			if !info.IsDir() {
				return fail(409, "directory_conflict", "父目录与已有文件冲突")
			}
		} else if os.IsNotExist(err) {
			if !withinAny(current, f.MkdirRoots) {
				return fail(403, "mkdir_denied", "创建目录需要 sftp.mkdir 权限")
			}
			if err = f.SFTP.Mkdir(current); err != nil {
				return fail(502, "mkdir_failed", "无法创建目标目录")
			}
		} else {
			return err
		}
	}
	return nil
}

var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (a *App) upload(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	t, e := a.task(ctx, u, r.PathValue("id"))
	if e != nil {
		return e
	}
	if t.Direction != "upload" || !contains([]string{"queued", "running", "paused", "partial"}, t.State) {
		return fail(409, "task_state", "任务当前不能上传")
	}
	lock := a.taskLock(t.ID)
	lock.Lock()
	defer lock.Unlock()
	t, e = a.task(ctx, u, t.ID)
	if e != nil {
		return e
	}
	if !contains([]string{"queued", "running", "paused", "partial"}, t.State) {
		return fail(409, "task_state", "任务不能上传")
	}
	itemID := r.PathValue("item")
	var item ManifestItem
	var offset int64
	var temp, state string
	e = a.store(ctx).QueryRow(ctx, "SELECT relative_path,is_directory,size,modified_ms,sha256,offset_bytes,COALESCE(temp_path,''),state FROM ra_transfer_items WHERE task_id=$1 AND id=$2", t.ID, itemID).Scan(&item.Path, &item.Directory, &item.Size, &item.Modified, &item.SHA, &offset, &temp, &state)
	if e != nil {
		return fail(404, "item_not_found", "任务条目不存在")
	}
	if state == "completed" || state == "skipped" || state == "cancelled" {
		return fail(409, "item_completed", "该文件已经提交")
	}
	f, e := a.fileConn(ctx, u, t.Account, "sftp.upload")
	if e != nil {
		return e
	}
	defer f.Close()
	if e = a.mkdirParents(f, t.Target, path.Dir(item.Path)); e != nil {
		return e
	}
	final := path.Join(t.Target, item.Path)
	if item.Directory {
		if e = a.mkdirParents(f, t.Target, item.Path); e != nil {
			return e
		}
		_, e = a.store(ctx).Exec(ctx, "UPDATE ra_transfer_items SET state='completed',final_path=$1 WHERE id=$2", final, itemID)
		if e != nil {
			return e
		}
		jsonOut(w, 200, map[string]any{"offset": 0, "completed": true})
		return nil
	}
	start, e := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if e != nil || start < 0 {
		return fail(400, "upload_offset", "上传偏移无效")
	}
	length := r.ContentLength
	if length < 0 || length > 4<<20 || start+length > item.Size {
		return fail(413, "chunk_limit", "分块长度无效或超过 4 MiB")
	}
	want := r.Header.Get("Upload-SHA256")
	if !shaPattern.MatchString(want) {
		return fail(400, "chunk_checksum", "每块需提供 SHA-256")
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if e != nil {
		return fail(413, "chunk_limit", "上传块超过上限")
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != want || int64(len(body)) != length {
		return fail(409, "checksum_mismatch", "上传块摘要或长度不一致")
	}
	if start < offset || item.Size == 0 && state == "running" {
		var oldSize int64
		var oldSHA string
		e = a.store(ctx).QueryRow(ctx, "SELECT size,sha256 FROM ra_transfer_chunks WHERE item_id=$1 AND offset_bytes=$2", itemID, start).Scan(&oldSize, &oldSHA)
		if e == nil && oldSize == length && oldSHA == want {
			jsonOut(w, 200, map[string]any{"offset": offset, "replayed": true})
			return nil
		}
		return fail(409, "chunk_conflict", "重试数据与已确认块不一致")
	}
	if start != offset {
		return fail(409, "offset_mismatch", "请按服务端确认的偏移继续")
	}
	if temp == "" {
		temp = path.Join(path.Dir(final), ".infrascope-"+t.ID+"-"+itemID+".part")
		if _, e = f.resolve(temp, true, true); e != nil {
			return e
		}
		file, e := f.SFTP.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
		if e != nil {
			return fail(409, "temporary_conflict", "无法安全创建临时文件")
		}
		file.Close()
		if _, e = a.store(ctx).Exec(ctx, "UPDATE ra_transfer_items SET temp_path=$1 WHERE id=$2", temp, itemID); e != nil {
			return e
		}
	}
	temp, e = f.resolve(temp, true, false)
	if e != nil {
		return e
	}
	remote, e := f.SFTP.OpenFile(temp, os.O_WRONLY)
	if e != nil {
		return fail(502, "upload_open_failed", "远端临时文件无法写入")
	}
	defer remote.Close()
	info, e := remote.Stat()
	if e != nil || info.Size() < offset {
		return fail(409, "remote_offset_changed", "远端临时文件已改变，需重新创建任务")
	}
	if offset > 0 && (t.State == "paused" || info.Size() != offset) {
		if e = a.verifyChunks(ctx, f, itemID, temp, offset); e != nil {
			return e
		}
	}
	if info.Size() > offset {
		if e = remote.Truncate(offset); e != nil {
			return fail(409, "truncate_failed", "无法恢复未确认的上传块")
		}
	}
	if e = a.takeBandwidth(ctx, u, int64(len(body))); e != nil {
		return e
	}
	if _, e = remote.WriteAt(body, offset); e != nil {
		_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state='paused',error_code='remote_write_failed' WHERE id=$1", t.ID)
		return fail(502, "remote_write_failed", "远端写入失败，可能有未确认的部分数据")
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "INSERT INTO ra_transfer_chunks(item_id,offset_bytes,size,sha256) VALUES($1,$2,$3,$4)", itemID, offset, length, want); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE ra_transfer_items SET offset_bytes=$1,state='running' WHERE id=$2", offset+length, itemID); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE ra_transfers SET state='running',done_bytes=done_bytes+$1,updated_at=now(),error_code=NULL WHERE id=$2", length, t.ID); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]any{"offset": offset + length, "completed": false})
	return nil
}
func (a *App) verifyChunks(ctx context.Context, f *FileConn, itemID, temp string, offset int64) error {
	rows, e := a.store(ctx).Query(ctx, "SELECT offset_bytes,size,sha256 FROM ra_transfer_chunks WHERE item_id=$1 ORDER BY offset_bytes", itemID)
	if e != nil {
		return e
	}
	defer rows.Close()
	file, e := f.SFTP.Open(temp)
	if e != nil {
		return e
	}
	defer file.Close()
	var pos int64
	fullHash := sha256.New()
	buf := make([]byte, 4<<20)
	for rows.Next() {
		var start int64
		var size int
		var want string
		if e = rows.Scan(&start, &size, &want); e != nil {
			return e
		}
		if start != pos || size < 0 || size > len(buf) {
			return fail(409, "chunk_history_invalid", "上传块记录不连续")
		}
		n, e := file.ReadAt(buf[:size], start)
		if e != nil && e != io.EOF || n != size {
			return fail(409, "remote_checksum_failed", "远端临时内容与已确认数据不一致")
		}
		fullHash.Write(buf[:size])
		sum := sha256.Sum256(buf[:size])
		if hex.EncodeToString(sum[:]) != want {
			return fail(409, "remote_checksum_failed", "远端临时内容被修改")
		}
		pos += int64(size)
	}
	if pos != offset {
		return fail(409, "chunk_history_invalid", "上传偏移与块记录不一致")
	}
	if e = rows.Err(); e != nil {
		return e
	}
	rows.Close()
	var expected string
	var total int64
	if e = a.store(ctx).QueryRow(ctx, "SELECT sha256,size FROM ra_transfer_items WHERE id=$1", itemID).Scan(&expected, &total); e != nil {
		return e
	}
	if expected != "" && offset == total && hex.EncodeToString(fullHash.Sum(nil)) != expected {
		return fail(409, "file_checksum_failed", "完整文件摘要不一致")
	}
	return nil
}
func (a *App) commitTransfer(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	t, e := a.task(ctx, u, r.PathValue("id"))
	if e != nil {
		return e
	}
	if t.Direction != "upload" {
		return fail(409, "upload_required", "仅上传任务可提交")
	}
	if t.State == "completed" {
		jsonOut(w, 200, map[string]string{"state": "completed"})
		return nil
	}
	if !contains([]string{"running", "queued", "paused", "partial"}, t.State) {
		return fail(409, "task_state", "任务不能提交")
	}
	lock := a.taskLock(t.ID)
	lock.Lock()
	defer lock.Unlock()
	t, e = a.task(ctx, u, t.ID)
	if e != nil {
		return e
	}
	if !contains([]string{"running", "queued", "paused", "partial"}, t.State) {
		return fail(409, "task_state", "任务不能提交")
	}
	f, e := a.fileConn(ctx, u, t.Account, "sftp.upload")
	if e != nil {
		return e
	}
	defer f.Close()
	rows, e := a.list(ctx, "SELECT id,relative_path,is_directory,size,offset_bytes,COALESCE(temp_path,'') AS temp_path,state,sha256 FROM ra_transfer_items WHERE task_id=$1 ORDER BY is_directory DESC,relative_path", t.ID)
	if e != nil {
		return e
	}
	failures := 0
	for _, m := range rows {
		if e = a.validLogin(ctx, u); e != nil {
			return e
		}
		if _, e = a.task(ctx, u, t.ID); e != nil {
			return e
		}
		id := m["id"].(string)
		state := m["state"].(string)
		if state == "cancelled" {
			failures++
			continue
		}
		if state == "completed" || state == "skipped" {
			continue
		}
		rel := m["relative_path"].(string)
		size := m["size"].(int64)
		offset := m["offset_bytes"].(int64)
		temp := m["temp_path"].(string)
		final := path.Join(t.Target, rel)
		code := ""
		if e = a.mkdirParents(f, t.Target, path.Dir(rel)); e != nil {
			code = "parent_failed"
		} else if m["is_directory"].(bool) {
			if e = a.mkdirParents(f, t.Target, rel); e != nil {
				code = "mkdir_failed"
			}
		} else if offset != size || temp == "" {
			code = "upload_incomplete"
		} else {
			if _, e = f.resolve(temp, true, false); e != nil {
				code = "temporary_changed"
			} else if e = a.verifyChunks(ctx, f, id, temp, offset); e != nil {
				code = "checksum_failed"
			} else if _, e = f.resolve(final, true, true); e != nil {
				code = "path_denied"
			} else {
				if _, statErr := f.SFTP.Lstat(final); statErr == nil {
					switch t.Conflict {
					case "ask":
						code = "name_conflict"
					case "skip":
						_ = f.SFTP.Remove(temp)
						_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfer_items SET state='skipped',temp_path=NULL WHERE id=$1", id)
						continue
					case "rename":
						ext := path.Ext(final)
						final = strings.TrimSuffix(final, ext) + " (" + id[:8] + ")" + ext
						if _, err := f.SFTP.Lstat(final); err == nil {
							code = "name_conflict"
						}
					case "overwrite":
						if !f.Policy.Limits.AllowOverwrite {
							code = "overwrite_denied"
						}
					}
				}
				if code == "" {
					if t.Conflict == "overwrite" {
						if _, ok := f.SFTP.HasExtension("posix-rename@openssh.com"); !ok {
							code = "atomic_overwrite_unsupported"
						} else {
							e = f.SFTP.PosixRename(temp, final)
						}
					} else {
						e = f.SFTP.Rename(temp, final)
					}
					if e != nil {
						code = "commit_failed"
					}
				}
			}
		}
		if code != "" {
			failures++
			_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfer_items SET state='failed',error_code=$1,retries=retries+1 WHERE id=$2", code, id)
		} else {
			_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfer_items SET state='completed',final_path=$1,temp_path=NULL,error_code=NULL WHERE id=$2", final, id)
		}
	}
	state := "completed"
	if failures > 0 {
		state = "partial"
	}
	_, e = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state=$1,updated_at=now() WHERE id=$2", state, t.ID)
	if e != nil {
		return e
	}
	if e = a.audit(ctx, u, "transfer.upload", t.Account, state, t.ID, map[string]any{"failedItems": failures}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]any{"state": state, "failedItems": failures})
	return nil
}
func (a *App) cancelTransfer(w http.ResponseWriter, r *http.Request, u *User) error {
	t, e := a.task(r.Context(), u, r.PathValue("id"))
	if e != nil {
		return e
	}
	if t.Direction == "upload" {
		lock := a.taskLock(t.ID)
		lock.Lock()
		defer lock.Unlock()
	}
	t, e = a.task(r.Context(), u, t.ID)
	if e != nil {
		return e
	}
	if t.State == "completed" {
		return fail(409, "task_completed", "已完成文件不会因取消而被删除")
	}
	_, e = a.DB.Exec(r.Context(), "UPDATE ra_transfers SET state='cancelled',updated_at=now() WHERE id=$1", t.ID)
	if e != nil {
		return e
	}
	a.cleanupTask(r.Context(), u, t)
	if e = a.audit(r.Context(), u, "transfer.cancel", t.Account, "cancelled", t.ID, map[string]any{}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]string{"state": "cancelled"})
	return nil
}
func (a *App) cleanupTask(ctx context.Context, u *User, t Transfer) {
	f, e := a.fileConn(ctx, u, t.Account, "sftp.upload")
	if e != nil {
		return
	}
	defer f.Close()
	items, e := a.list(ctx, "SELECT id,temp_path FROM ra_transfer_items WHERE task_id=$1 AND temp_path IS NOT NULL AND (state='cancelled' OR EXISTS(SELECT 1 FROM ra_transfers WHERE id=$1 AND state IN('cancelled','failed')))", t.ID)
	if e != nil {
		return
	}
	for _, x := range items {
		p := x["temp_path"].(string)
		if path.Base(p) != ".infrascope-"+t.ID+"-"+x["id"].(string)+".part" {
			continue
		}
		if _, e = f.resolve(p, true, false); e == nil {
			if e = f.SFTP.Remove(p); e == nil {
				_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfer_items SET temp_path=NULL WHERE id=$1", x["id"])
			}
		}
	}
}
func (a *App) download(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	t, e := a.task(ctx, u, r.PathValue("id"))
	if e != nil {
		return e
	}
	if t.Direction != "download" || !contains([]string{"queued", "failed", "partial"}, t.State) {
		return fail(409, "download_state", "该任务不能下载，请为重试创建新任务")
	}
	lock := a.taskLock(t.ID)
	lock.Lock()
	defer lock.Unlock()
	f, e := a.fileConn(ctx, u, t.Account, "sftp.download")
	if e != nil {
		return e
	}
	defer f.Close()
	items, e := a.list(ctx, "SELECT id,relative_path,is_directory,size,modified_ms FROM ra_transfer_items WHERE task_id=$1 ORDER BY relative_path", t.ID)
	if e != nil {
		return e
	}
	_, e = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state='running',done_bytes=0,updated_at=now() WHERE id=$1", t.ID)
	if e != nil {
		return e
	}
	single := len(items) == 1 && !items[0]["is_directory"].(bool) && r.URL.Query().Get("format") == "file"
	name := "infrascope-" + t.ID[:8] + ".zip"
	if single {
		name = path.Base(items[0]["relative_path"].(string))
	}
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Transfer-Id", t.ID)
	w.Header().Set("Content-Type", "application/zip")
	if single {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", formatInt(items[0]["size"].(int64)))
	}
	var zw *zip.Writer
	if !single {
		zw = zip.NewWriter(w)
	}
	var transferred int64
	failure := ""
	for _, m := range items {
		if _, e = a.task(ctx, u, t.ID); e != nil {
			failure = "authorization_changed"
			break
		}
		var currentState string
		if e = a.store(ctx).QueryRow(ctx, "SELECT state FROM ra_transfers WHERE id=$1", t.ID).Scan(&currentState); e != nil || currentState == "cancelled" {
			failure = "cancelled"
			break
		}
		rel := m["relative_path"].(string)
		full, e := f.resolve(path.Join(t.Target, rel), false, false)
		if e != nil {
			failure = "path_changed"
			break
		}
		info, e := f.SFTP.Stat(full)
		if e != nil || info.IsDir() != m["is_directory"].(bool) || !info.IsDir() && (info.Size() != m["size"].(int64) || info.ModTime().UnixMilli() != m["modified_ms"].(int64)) {
			failure = "source_changed"
			break
		}
		var dst io.Writer = w
		if !single {
			h := &zip.FileHeader{Name: rel, Method: zip.Deflate}
			h.SetModTime(info.ModTime())
			h.SetMode(info.Mode())
			if info.IsDir() {
				h.Name += "/"
				h.Method = zip.Store
			}
			dst, e = zw.CreateHeader(h)
			if e != nil {
				failure = "archive_failed"
				break
			}
		}
		if !info.IsDir() {
			file, e := f.SFTP.Open(full)
			if e != nil {
				failure = "source_unavailable"
				break
			}
			buf := make([]byte, 64<<10)
			var count int64
			lastCheck := time.Time{}
			for {
				if time.Since(lastCheck) > time.Second {
					if _, e = a.task(ctx, u, t.ID); e != nil {
						failure = "authorization_changed"
						break
					}
					var st string
					_ = a.store(ctx).QueryRow(ctx, "SELECT state FROM ra_transfers WHERE id=$1", t.ID).Scan(&st)
					if st == "cancelled" {
						failure = "cancelled"
						break
					}
					lastCheck = time.Now()
				}
				n, readErr := file.Read(buf)
				if n > 0 {
					if e = a.takeBandwidth(ctx, u, int64(n)); e != nil {
						failure = "response_interrupted"
						break
					}
					nw, writeErr := dst.Write(buf[:n])
					count += int64(nw)
					transferred += int64(nw)
					if writeErr != nil || nw != n {
						failure = "response_interrupted"
						break
					}
					_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET done_bytes=$1,updated_at=now() WHERE id=$2", transferred, t.ID)
				}
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					failure = "source_read_failed"
					break
				}
			}
			file.Close()
			after, e := f.SFTP.Stat(full)
			if failure == "" && (e != nil || count != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime())) {
				failure = "source_changed"
			}
			if failure != "" {
				_, _ = a.DB.Exec(context.Background(), "UPDATE ra_transfer_items SET state='failed',error_code=$1 WHERE id=$2", failure, m["id"])
				break
			}
		}
		_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfer_items SET state='completed',offset_bytes=size WHERE id=$1", m["id"])
	}
	if zw != nil {
		if e = zw.Close(); e != nil && failure == "" {
			failure = "archive_close_failed"
		}
	}
	state := "completed"
	if failure != "" {
		state = "failed"
		if transferred > 0 {
			state = "partial"
		}
		if failure == "cancelled" {
			state = "cancelled"
		}
	}
	endCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = a.DB.Exec(endCtx, "UPDATE ra_transfers SET state=$1,error_code=NULLIF($2,''),done_bytes=$3,updated_at=now() WHERE id=$4", state, failure, transferred, t.ID)
	_ = a.audit(endCtx, u, "transfer.download", t.Account, state, t.ID, map[string]any{"bytesWrittenToResponse": transferred, "browserSavedUnknown": true})
	return nil
}
func (a *App) cleanup(ctx context.Context) {
	_, _ = a.store(ctx).Exec(ctx, "DELETE FROM ra_attach_tokens WHERE expires_at<now()-interval '1 hour'")
	_, _ = a.store(ctx).Exec(ctx, "DELETE FROM ra_device_nonces WHERE expires_at<now()")
	_, _ = a.store(ctx).Exec(ctx, "DELETE FROM ra_login_sessions WHERE expires_at<now()")
	_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_rdp_launches SET state='expired' WHERE state='queued' AND expires_at<now()")
	_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state='paused',error_code='waiting_for_browser' WHERE direction='upload' AND state='running' AND updated_at<now()-interval '60 seconds'")
	_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state='failed',error_code='task_expired' WHERE expires_at<now() AND state IN('queued','running','paused','scanning')")
}

// Transfer control changes stored state only after ownership and current grants are checked.
func (a *App) transferControl(w http.ResponseWriter, r *http.Request, u *User) error {
	t, e := a.task(r.Context(), u, r.PathValue("id"))
	if e != nil {
		return e
	}
	var in struct {
		Action   string `json:"action"`
		Item     string `json:"itemId"`
		Conflict string `json:"conflict"`
		Confirm  bool   `json:"confirm"`
	}
	if e = decode(w, r, &in); e != nil {
		return e
	}
	if t.Direction != "upload" {
		return fail(409, "stream_not_resumable", "流式下载不能暂停续传，请重新下载")
	}
	lock := a.taskLock(t.ID)
	lock.Lock()
	defer lock.Unlock()
	switch in.Action {
	case "pause":
		if !contains([]string{"running", "queued"}, t.State) {
			return fail(409, "task_state", "无法暂停此任务")
		}
		_, e = a.DB.Exec(r.Context(), "UPDATE ra_transfers SET state='paused',updated_at=now() WHERE id=$1", t.ID)
	case "retry":
		if !contains([]string{"partial", "paused"}, t.State) {
			return fail(409, "task_state", "任务不能重试")
		}
		if !contains([]string{"ask", "skip", "rename", "overwrite"}, in.Conflict) {
			return fail(400, "conflict_policy", "同名策略无效")
		}
		if in.Conflict == "overwrite" {
			x, err := a.account(r.Context(), u, t.Account)
			if err != nil {
				return err
			}
			p, err := a.policy(r.Context(), u, x, "sftp", "sftp.upload")
			if err != nil {
				return err
			}
			if !p.Limits.AllowOverwrite || !in.Confirm {
				return fail(403, "overwrite_denied", "覆盖需权限与确认")
			}
		}
		_, e = a.DB.Exec(r.Context(), "UPDATE ra_transfers SET state='paused',conflict=$1,error_code=NULL,updated_at=now() WHERE id=$2", in.Conflict, t.ID)
	case "cancel_item":
		res, err := a.DB.Exec(r.Context(), "UPDATE ra_transfer_items SET state='cancelled',error_code='user_cancelled' WHERE id=$1 AND task_id=$2 AND state NOT IN('completed','skipped')", in.Item, t.ID)
		e = err
		if err == nil && res.RowsAffected() != 1 {
			return fail(404, "item_not_found", "条目不存在或已完成")
		}
	default:
		return fail(400, "control_action", "控制动作无效")
	}
	if e != nil {
		return e
	}
	if e = a.audit(r.Context(), u, "transfer."+in.Action, t.Account, "success", t.ID, map[string]string{"itemId": in.Item}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
	return nil
}

func (a *App) retryCleanup(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	rows, e := a.list(ctx, `SELECT t.id,t.workspace,t.user_id,t.login_id_hash,t.account_id,u.role FROM ra_transfers t JOIN ra_users u ON u.id=t.user_id WHERE t.gateway_id=$1 AND t.direction='upload' AND t.state IN('cancelled','failed','partial') AND u.enabled AND EXISTS(SELECT 1 FROM ra_transfer_items i WHERE i.task_id=t.id AND i.temp_path IS NOT NULL AND (i.state='cancelled' OR t.state IN('cancelled','failed'))) ORDER BY t.updated_at LIMIT 3`, a.Config.GatewayID)
	if e != nil {
		return
	}
	for _, r := range rows {
		u := &User{ID: r["user_id"].(string), Workspace: r["workspace"].(string), LoginHash: r["login_id_hash"].(string), Role: r["role"].(string)}
		if a.validLogin(ctx, u) != nil {
			continue
		}
		t := Transfer{ID: r["id"].(string), Account: r["account_id"].(string)}
		a.cleanupTask(ctx, u, t)
	}
}
