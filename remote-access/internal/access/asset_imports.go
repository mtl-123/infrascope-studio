package access

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type ImportRow struct {
	RowNumber   int        `json:"rowNumber"`
	InventoryID string     `json:"inventoryId"`
	Name        string     `json:"name"`
	State       string     `json:"state"`
	Message     string     `json:"message"`
	AssetID     string     `json:"assetId,omitempty"`
	Payload     AssetInput `json:"payload"`
}

type ImportJob struct {
	ID             string         `json:"id"`
	Source         string         `json:"source"`
	State          string         `json:"state"`
	Rows           []ImportRow    `json:"rows"`
	Facts          map[string]any `json:"facts"`
	ClaimantID     string         `json:"claimantId"`
	OrganizationID string         `json:"organizationId"`
	ExpiresAt      time.Time      `json:"expiresAt"`
	CreatedAt      time.Time      `json:"createdAt"`
	Counts         map[string]int `json:"counts"`
}

func (j *ImportJob) count() {
	j.Counts = map[string]int{"ready": 0, "invalid": 0, "duplicate": 0, "created": 0, "failed": 0}
	for _, row := range j.Rows {
		j.Counts[row.State]++
	}
}

func scanImport(row pgx.Row) (ImportJob, error) {
	var job ImportJob
	var rows, facts []byte
	err := row.Scan(&job.ID, &job.Source, &job.State, &rows, &facts, &job.ClaimantID, &job.OrganizationID, &job.ExpiresAt, &job.CreatedAt)
	if err != nil {
		return job, err
	}
	if err = json.Unmarshal(rows, &job.Rows); err != nil {
		return job, err
	}
	if err = json.Unmarshal(facts, &job.Facts); err != nil {
		return job, err
	}
	job.count()
	return job, nil
}

const importJobSelect = `SELECT id,source_kind,state,rows,facts,claimant_id,COALESCE(organization_id,''),expires_at,created_at FROM ra_asset_import_jobs WHERE workspace=$1 AND id=$2 AND (created_by=$3 OR $4='admin')`

func (a *App) importJobs(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := require(u, "asset.manage"); err != nil {
		return err
	}
	if id := r.PathValue("id"); id != "" {
		job, err := scanImport(a.DB.QueryRow(r.Context(), importJobSelect, u.Workspace, id, u.ID, u.Role))
		if errors.Is(err, pgx.ErrNoRows) {
			return fail(404, "import_not_found", "导入任务不存在或无权访问")
		}
		if err != nil {
			return err
		}
		jsonOut(w, 200, job)
		return nil
	}
	rows, err := a.DB.Query(r.Context(), `SELECT id,source_kind,state,rows,facts,claimant_id,COALESCE(organization_id,''),expires_at,created_at FROM ra_asset_import_jobs WHERE workspace=$1 AND (created_by=$2 OR $3='admin') ORDER BY created_at DESC,id LIMIT 100`, u.Workspace, u.ID, u.Role)
	if err != nil {
		return err
	}
	defer rows.Close()
	jobs := []ImportJob{}
	for rows.Next() {
		job, err := scanImport(rows)
		if err != nil {
			return err
		}
		jobs = append(jobs, job)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	jsonOut(w, 200, jobs)
	return nil
}

func parseAssetCSV(text, claimant, organization string) ([]ImportRow, error) {
	if len(text) == 0 || len(text) > 512*1024 || !utf8.ValidString(text) {
		return nil, fail(400, "import_size", "CSV 必须非空且不超过 512 KiB")
	}
	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(text, "\ufeff")))
	head, err := reader.Read()
	if err != nil {
		return nil, fail(400, "import_csv", "CSV 表头无法解析")
	}
	allowed := []string{"inventoryId", "name", "category", "kind", "osFamily", "environment", "site", "business", "description"}
	seenHead := map[string]bool{}
	for _, field := range head {
		if !contains(allowed, field) || seenHead[field] {
			return nil, fail(400, "import_headers", "CSV 包含未知或重复列；不接受密码、端点或权限字段")
		}
		seenHead[field] = true
	}
	if !seenHead["inventoryId"] || !seenHead["name"] {
		return nil, fail(400, "import_headers", "CSV 必须包含 inventoryId 和 name 列")
	}
	rows := []ImportRow{}
	seen := map[string]bool{}
	for {
		fields, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fail(400, "import_csv", "CSV 行格式错误或列数不一致")
		}
		if len(rows) == 200 {
			return nil, fail(400, "import_limit", "每次预览最多 200 行")
		}
		values := map[string]string{}
		for i, field := range head {
			values[field] = strings.TrimSpace(fields[i])
		}
		category, kind, os := values["category"], values["kind"], values["osFamily"]
		if category == "" {
			category = "server"
		}
		if kind == "" {
			kind = "physical"
		}
		if os == "" {
			os = "other"
		}
		environment, site, business := values["environment"], values["site"], values["business"]
		payload := AssetInput{Name: values["name"], Inventory: values["inventoryId"], Category: &category, Kind: kind, OS: os, Environment: &environment, Site: &site, Business: &business, Description: values["description"], Tags: []string{}, Metadata: map[string]string{}, Enabled: true, Endpoints: []Endpoint{}, OrganizationID: &organization, Ownership: &Ownership{State: "pending", ClaimantID: claimant, NotificationIDs: []string{}, BackupIDs: []string{}}}
		row := ImportRow{RowNumber: len(rows) + 1, InventoryID: payload.Inventory, Name: payload.Name, State: "ready", Message: "待确认；不会自动连接或采集", Payload: payload}
		if !bounded(payload.Inventory, 180) || !bounded(payload.Name, 180) || !contains([]string{"server", "nas", "pve", "switch", "printer", "scanner", "other"}, category) || !contains([]string{"physical", "virtual"}, kind) || !contains([]string{"linux", "windows", "other"}, os) || !optionalText(environment, 120) || !optionalText(site, 120) || !optionalText(business, 120) || len(payload.Description) > 2000 {
			row.State, row.Message = "invalid", "名称、inventoryId、类别、系统或字段长度无效"
		} else if seen[payload.Inventory] {
			row.State, row.Message = "duplicate", "本批次 inventoryId 重复；不会覆盖先前行"
		}
		seen[payload.Inventory] = true
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, fail(400, "import_empty", "CSV 没有数据行")
	}
	return rows, nil
}

func (a *App) previewImport(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := require(u, "asset.manage"); err != nil {
		return err
	}
	var in struct {
		CSV          string `json:"csv"`
		Claimant     string `json:"claimantId"`
		Organization string `json:"organizationId"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	rows, err := parseAssetCSV(in.CSV, in.Claimant, in.Organization)
	if err != nil {
		return err
	}
	return a.createImportPreview(w, r, u, "csv", in.Claimant, in.Organization, rows, map[string]any{"source": "uploaded_csv", "automaticDiscovery": false})
}

func (a *App) createImportPreview(w http.ResponseWriter, r *http.Request, u *User, source, claimant, organization string, rows []ImportRow, facts map[string]any) error {
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var person string
	if !bounded(claimant, 120) {
		return fail(400, "claimant_required", "请明确选择待认领责任人")
	}
	if err = tx.QueryRow(ctx, "SELECT id FROM ra_people WHERE workspace=$1 AND id=$2 AND enabled FOR SHARE", u.Workspace, claimant).Scan(&person); errors.Is(err, pgx.ErrNoRows) {
		return fail(400, "claimant_invalid", "责任人不存在、停用或不属于当前工作空间")
	} else if err != nil {
		return err
	}
	if err = a.validateAssetOrganization(ctx, tx, u, organization); err != nil {
		return err
	}
	for i := range rows {
		if rows[i].State != "ready" {
			continue
		}
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ra_assets WHERE workspace=$1 AND inventory_id=$2)", u.Workspace, rows[i].InventoryID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			rows[i].State, rows[i].Message = "duplicate", "此 inventoryId 已登记；不会覆盖已有资产或负责人"
		}
	}
	job := ImportJob{ID: ID(), Source: source, State: "preview", Rows: rows, Facts: facts, ClaimantID: claimant, OrganizationID: organization, ExpiresAt: time.Now().UTC().Add(30 * time.Minute), CreatedAt: time.Now().UTC()}
	_, err = tx.Exec(ctx, `INSERT INTO ra_asset_import_jobs(id,workspace,created_by,source_kind,state,rows,facts,claimant_id,organization_id,expires_at,created_at) VALUES($1,$2,$3,$4,'preview',$5,$6,$7,NULLIF($8,''),$9,$10)`, job.ID, u.Workspace, u.ID, source, marshal(rows), marshal(facts), claimant, organization, job.ExpiresAt, job.CreatedAt)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'asset_import.preview',$3,'success',$4)`, u.Workspace, u.ID, job.ID, marshal(map[string]any{"source": source, "rows": len(rows)})); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	job.count()
	jsonOut(w, 200, job)
	return nil
}

func (a *App) confirmImport(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := require(u, "asset.manage"); err != nil {
		return err
	}
	var in struct {
		Confirm bool  `json:"confirm"`
		Rows    []int `json:"rowNumbers"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if !in.Confirm || len(in.Rows) == 0 || len(in.Rows) > 200 {
		return fail(400, "import_confirmation", "请明确确认并选择 1–200 行")
	}
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	job, err := scanImport(tx.QueryRow(ctx, importJobSelect+" FOR UPDATE", u.Workspace, r.PathValue("id"), u.ID, u.Role))
	if errors.Is(err, pgx.ErrNoRows) {
		return fail(404, "import_not_found", "导入任务不存在或无权访问")
	}
	if err != nil {
		return err
	}
	if job.State == "cancelled" {
		return fail(409, "import_cancelled", "任务已取消，已创建资产不会删除")
	}
	if !job.ExpiresAt.After(time.Now()) {
		return fail(410, "import_expired", "预览已过期，请重新预览并确认")
	}
	observedAt := job.CreatedAt
	if job.Source == "local_discovery" {
		stamp, ok := job.Facts["observedAt"].(string)
		if !ok {
			return errors.New("discovery observation timestamp missing")
		}
		observedAt, err = time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			return err
		}
	}
	selected := map[int]bool{}
	for _, number := range in.Rows {
		if number < 1 || number > len(job.Rows) || selected[number] {
			return fail(400, "import_rows", "所选行无效或重复")
		}
		if state := job.Rows[number-1].State; state != "ready" && state != "failed" && state != "created" {
			return fail(400, "import_rows", "仅可确认可导入行或重试失败行")
		}
		selected[number] = true
	}
	order := make([]int, len(job.Rows))
	for i := range order {
		order[i] = i
	}
	// A stable identity order prevents opposite CSV orders from deadlocking unique inserts.
	sort.Slice(order, func(i, j int) bool { return job.Rows[order[i]].InventoryID < job.Rows[order[j]].InventoryID })
	for _, i := range order {
		row := &job.Rows[i]
		if !selected[row.RowNumber] || row.State == "created" {
			continue
		}
		sp, e := tx.Begin(ctx)
		if e != nil {
			return e
		}
		var exists bool
		if e = sp.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ra_assets WHERE workspace=$1 AND inventory_id=$2)", u.Workspace, row.InventoryID).Scan(&exists); e != nil {
			sp.Rollback(ctx)
			return e
		}
		if exists {
			sp.Rollback(ctx)
			row.State, row.Message = "duplicate", "确认时发现重复 inventoryId；未覆盖已有资产"
			continue
		}
		asset, e := a.saveAsset(ctx, sp, u, "", row.Payload)
		if e == nil {
			_, e = sp.Exec(ctx, `INSERT INTO ra_asset_origins(workspace,asset_id,source_kind,source_job_id,observed_at,facts) VALUES($1,$2,$3,$4,$5,$6)`, u.Workspace, asset, job.Source, job.ID, observedAt, marshal(job.Facts))
		}
		if e != nil {
			sp.Rollback(ctx)
			var apiErr *apiError
			var pgErr *pgconn.PgError
			if errors.As(e, &pgErr) && pgErr.Code == "23505" {
				row.State, row.Message = "duplicate", "确认时 inventoryId 已被其他任务登记"
				continue
			}
			if errors.As(e, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 {
				row.State, row.Message = "failed", apiErr.Message
				continue
			}
			return e
		}
		if e = sp.Commit(ctx); e != nil {
			return e
		}
		row.State, row.Message, row.AssetID = "created", "已登记真实资产；尚未连接或采集", asset
	}
	job.count()
	job.State = "confirmed"
	for _, row := range job.Rows {
		if row.State != "created" && row.State != "duplicate" {
			job.State = "partial"
			break
		}
	}
	if _, err = tx.Exec(ctx, "UPDATE ra_asset_import_jobs SET state=$1,rows=$2,updated_at=now() WHERE workspace=$3 AND id=$4", job.State, marshal(job.Rows), u.Workspace, job.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'asset_import.confirm',$3,$4,$5)`, u.Workspace, u.ID, job.ID, job.State, marshal(job.Counts)); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	jsonOut(w, 200, job)
	return nil
}

func (a *App) cancelImport(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := require(u, "asset.manage"); err != nil {
		return err
	}
	var in struct {
		Confirm bool `json:"confirm"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if !in.Confirm {
		return fail(400, "import_confirmation", "请明确确认取消未创建行")
	}
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	job, err := scanImport(tx.QueryRow(ctx, importJobSelect+" FOR UPDATE", u.Workspace, r.PathValue("id"), u.ID, u.Role))
	if errors.Is(err, pgx.ErrNoRows) {
		return fail(404, "import_not_found", "任务不存在或无权访问")
	}
	if err != nil {
		return err
	}
	if job.State == "confirmed" {
		return fail(409, "import_completed", "已确认完成；不能用取消删除资产")
	}
	job.State = "cancelled"
	if _, err = tx.Exec(ctx, "UPDATE ra_asset_import_jobs SET state='cancelled',updated_at=now() WHERE workspace=$1 AND id=$2", u.Workspace, job.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result) VALUES($1,$2,'asset_import.cancel',$3,'cancelled')`, u.Workspace, u.ID, job.ID); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	jsonOut(w, 200, job)
	return nil
}
