package access

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"sort"
	"strconv"
	"strings"
)

func optionalText(value string, max int) bool {
	return len(value) <= max && !strings.ContainsAny(value, "\x00\r\n")
}

func (a *App) people(w http.ResponseWriter, r *http.Request, u *User) error {
	if !has(u, "asset.manage") {
		return fail(403, "permission_denied", "无权读取人员目录")
	}
	ctx := r.Context()
	if r.Method == "GET" {
		offset := 0
		if raw := r.URL.Query().Get("offset"); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 0 || value > 1000000 {
				return fail(400, "pagination_offset", "分页位置无效")
			}
			offset = value
		}
		search := strings.TrimSpace(r.URL.Query().Get("q"))
		if !optionalText(search, 200) {
			return fail(400, "search_length", "搜索文本无效或过长")
		}
		ids := []string{}
		if raw := r.URL.Query().Get("ids"); raw != "" {
			ids = strings.Split(raw, ",")
			if len(ids) > 20 {
				return fail(400, "people_limit", "一次最多读取 20 个人员引用")
			}
			for _, id := range ids {
				if !bounded(id, 120) {
					return fail(400, "person_id", "人员引用无效")
				}
			}
		}
		// Contact emails stay in the administrator directory, not asset or picker payloads.
		rows, err := a.list(ctx, `SELECT id,display_name,department,CASE WHEN $5 THEN email ELSE '' END AS email,contact_type,source,enabled,version,(email<>'') AS email_configured FROM ra_people WHERE workspace=$1 AND ($2='' OR display_name ILIKE '%'||$2||'%' OR department ILIKE '%'||$2||'%') AND (cardinality($4::text[])=0 OR id=ANY($4)) ORDER BY display_name,id LIMIT 100 OFFSET $3`, u.Workspace, search, offset, ids, has(u, "user.manage"))
		if err != nil {
			return err
		}
		jsonOut(w, 200, rows)
		return nil
	}
	if err := require(u, "user.manage"); err != nil {
		return err
	}
	var in struct {
		Name       string `json:"displayName"`
		Department string `json:"department"`
		Email      string `json:"email"`
		Type       string `json:"contactType"`
		Enabled    bool   `json:"enabled"`
		Version    int64  `json:"version"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	in.Name, in.Department, in.Email = strings.TrimSpace(in.Name), strings.TrimSpace(in.Department), strings.TrimSpace(in.Email)
	if !bounded(in.Name, 180) || !optionalText(in.Department, 240) || !optionalText(in.Email, 254) || !contains([]string{"internal", "external"}, in.Type) {
		return fail(400, "person_invalid", "人员名称、部门、邮箱或联系人类型无效")
	}
	if in.Email != "" {
		address, err := mail.ParseAddress(in.Email)
		if err != nil || address.Address != in.Email || address.Name != "" {
			return fail(400, "email_invalid", "请填写单个有效邮箱地址，不含显示名")
		}
	}
	id := r.PathValue("id")
	if id != "" && in.Version < 1 {
		return fail(400, "person_version_required", "更新人员必须携带当前版本")
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if id == "" {
		id = ID()
		_, err = tx.Exec(ctx, `INSERT INTO ra_people(id,workspace,display_name,department,email,contact_type,enabled,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, u.Workspace, in.Name, in.Department, in.Email, in.Type, in.Enabled, u.ID)
	} else {
		var current int64
		if err = tx.QueryRow(ctx, "SELECT version FROM ra_people WHERE workspace=$1 AND id=$2 FOR UPDATE", u.Workspace, id).Scan(&current); err != nil {
			return fail(404, "person_not_found", "人员不存在")
		}
		if current != in.Version {
			return fail(409, "person_version_conflict", "人员已被修改，请刷新核对后重试")
		}
		_, err = tx.Exec(ctx, `UPDATE ra_people SET display_name=$1,department=$2,email=$3,contact_type=$4,enabled=$5,version=version+1,updated_at=now() WHERE workspace=$6 AND id=$7`, in.Name, in.Department, in.Email, in.Type, in.Enabled, u.Workspace, id)
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'person.save',$3,'success',$4)`, u.Workspace, u.ID, id, marshal(map[string]any{"enabled": in.Enabled, "contactType": in.Type, "source": "manual"})); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	jsonOut(w, 200, map[string]string{"id": id})
	return nil
}

type Ownership struct {
	State           string   `json:"state"`
	UserID          string   `json:"userId"`
	ClaimantID      string   `json:"claimantId"`
	OperationsID    string   `json:"operationsId"`
	BusinessID      string   `json:"businessId"`
	NotificationIDs []string `json:"notificationIds"`
	BackupIDs       []string `json:"backupIds"`
}

func (o *Ownership) normalize() error {
	if o.State != "assigned" && o.State != "pending" || o.State == "assigned" && (o.UserID == "" || o.ClaimantID != "") || o.State == "pending" && (o.ClaimantID == "" || o.UserID != "") {
		return fail(400, "ownership_required", "必须指定使用人，或明确指定待认领责任人，两者不可混用")
	}
	for _, list := range []*[]string{&o.NotificationIDs, &o.BackupIDs} {
		if *list == nil {
			*list = []string{}
		}
		if len(*list) > 20 {
			return fail(400, "ownership_limit", "通知或备用责任人最多 20 人")
		}
		sort.Strings(*list)
		for i, id := range *list {
			if id == "" || i > 0 && id == (*list)[i-1] {
				return fail(400, "ownership_duplicate", "责任人引用为空或重复")
			}
		}
	}
	for _, id := range o.ids() {
		if !bounded(id, 120) {
			return fail(400, "ownership_person", "责任人员引用无效")
		}
	}
	return nil
}

func (o *Ownership) ids() []string {
	values := append([]string{o.UserID, o.ClaimantID, o.OperationsID, o.BusinessID}, o.NotificationIDs...)
	values = append(values, o.BackupIDs...)
	seen := map[string]bool{}
	ids := []string{}
	for _, id := range values {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (a *App) ownershipHistory(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := a.manageAsset(r.Context(), u, r.PathValue("id")); err != nil {
		return err
	}
	rows, err := a.list(r.Context(), `SELECT revision,ownership,people_snapshot,changed_by,changed_at FROM ra_asset_ownership_history WHERE workspace=$1 AND asset_id=$2 ORDER BY revision DESC LIMIT 100`, u.Workspace, r.PathValue("id"))
	if err != nil {
		return err
	}
	jsonOut(w, 200, rows)
	return nil
}

func sameOwnership(raw []byte, value *Ownership) bool {
	var previous Ownership
	if json.Unmarshal(raw, &previous) != nil || previous.normalize() != nil {
		return false
	}
	return string(marshal(previous)) == string(marshal(value))
}
