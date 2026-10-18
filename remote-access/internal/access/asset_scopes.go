package access

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const assetVisibilitySQL = `a.workspace=$1 AND (
 $2='admin' OR ($2='asset_manager' AND a.created_by=$3)
 OR ` + organizationVisibilitySQL + `
 OR EXISTS(SELECT 1 FROM ra_grants g JOIN ra_accounts ac ON ac.id=g.account_id AND ac.workspace=g.workspace
   WHERE g.workspace=a.workspace AND g.asset_id=a.id AND ac.asset_id=a.id AND ac.enabled AND NOT ac.archived
   AND g.actions ? 'asset.view' AND NOT g.revoked AND g.starts_at<=now() AND g.expires_at>now()
   AND (g.user_id=$3 OR g.group_id IN(SELECT group_id FROM ra_group_members WHERE workspace=$1 AND user_id=$3)))
 OR EXISTS(SELECT 1 FROM ra_asset_group_assets ga JOIN ra_asset_groups ag ON ag.id=ga.asset_group_id AND ag.workspace=ga.workspace
   WHERE ga.workspace=a.workspace AND ga.asset_id=a.id AND ag.enabled AND ag.starts_at<=now() AND ag.expires_at>now()
   AND (EXISTS(SELECT 1 FROM ra_asset_group_users gu WHERE gu.workspace=$1 AND gu.asset_group_id=ag.id AND gu.user_id=$3)
     OR EXISTS(SELECT 1 FROM ra_asset_group_subject_groups gg JOIN ra_group_members gm ON gm.workspace=gg.workspace AND gm.group_id=gg.group_id
       WHERE gg.workspace=$1 AND gg.asset_group_id=ag.id AND gm.user_id=$3)))
)`

const assetFiltersSQL = ` AND ($4='' OR a.id=$4)
 AND ($5='' OR a.name ILIKE '%'||$5||'%' OR a.kind ILIKE '%'||$5||'%' OR a.os_family ILIKE '%'||$5||'%'
   OR a.group_name ILIKE '%'||$5||'%' OR a.tags::text ILIKE '%'||$5||'%' OR a.category ILIKE '%'||$5||'%'
   OR a.environment ILIKE '%'||$5||'%' OR a.site ILIKE '%'||$5||'%' OR a.business ILIKE '%'||$5||'%')
 AND ($6='' OR a.category=$6) AND ($7='' OR a.environment=$7) AND ($8='' OR a.site=$8) AND ($9='' OR a.business=$9)
 AND ($10='' OR a.ownership->>'userId'=$10 OR a.ownership->>'claimantId'=$10)
 AND ($11='' OR EXISTS(SELECT 1 FROM ra_asset_group_assets fa WHERE fa.workspace=$1 AND fa.asset_id=a.id AND fa.asset_group_id=$11))
 AND (cardinality($12::text[])=0 OR a.id=ANY($12))`

const assetSelectSQL = `SELECT a.id,a.name,a.kind,a.os_family,a.group_name,a.tags,a.description,a.metadata,a.enabled,a.archived,a.version,a.inventory_id,
 a.category,a.environment,a.site,a.business,a.organization_id,a.ownership,a.ownership_legacy AS "ownershipLegacy",
 (SELECT json_build_object('kind',o.source_kind,'jobId',o.source_job_id,'observedAt',o.observed_at,'facts',o.facts) FROM ra_asset_origins o WHERE o.workspace=a.workspace AND o.asset_id=a.id) AS origin,
 ($2='admin' OR ($2='asset_manager' AND a.created_by=$3)) AS "canManage",
 COALESCE((SELECT json_agg(json_build_object('id',e.id,'protocol',e.protocol,'host',e.host,'port',e.port,'gatewayId',e.gateway_id,'version',e.version) ORDER BY e.protocol)
   FROM ra_endpoints e WHERE e.workspace=a.workspace AND e.asset_id=a.id),'[]') AS endpoints
 FROM ra_assets a WHERE ` + assetVisibilitySQL + assetFiltersSQL + ` ORDER BY a.name,a.id LIMIT $13 OFFSET $14`

func boundedIDs(ids []string, max int) ([]string, error) {
	if len(ids) > max {
		return nil, fail(400, "scope_limit", "范围引用超过上限")
	}
	if ids == nil {
		ids = []string{}
	}
	sort.Strings(ids)
	for i, id := range ids {
		if !bounded(id, 120) || strings.TrimSpace(id) != id || (i > 0 && ids[i-1] == id) {
			return nil, fail(400, "scope_reference", "范围引用为空、重复或无效")
		}
	}
	return ids, nil
}

func pageOffset(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(raw)
	if err != nil || offset < 0 || offset > 1000000 {
		return 0, fail(400, "pagination_offset", "分页位置无效")
	}
	return offset, nil
}

func (a *App) queryAssets(r *http.Request, u *User, limit int, exporting bool) ([]map[string]any, error) {
	if !has(u, "asset.view") {
		return nil, fail(403, "permission_denied", "无权查看资产")
	}
	query := r.URL.Query()
	offset, err := pageOffset(query.Get("offset"))
	if err != nil {
		return nil, err
	}
	if exporting || r.PathValue("id") != "" {
		offset = 0
	}
	ids := []string{}
	if raw := query.Get("ids"); raw != "" {
		ids, err = boundedIDs(strings.Split(raw, ","), 100)
		if err != nil {
			return nil, err
		}
	}
	values := []string{}
	for _, key := range []string{"q", "category", "environment", "site", "business", "ownerId", "groupId"} {
		value := strings.TrimSpace(query.Get(key))
		max := 120
		if key == "q" {
			max = 200
		}
		if !optionalText(value, max) {
			return nil, fail(400, "asset_filter", "资产筛选字段过长或无效")
		}
		values = append(values, value)
	}
	if values[1] != "" && !contains([]string{"server", "nas", "pve", "switch", "printer", "scanner", "other"}, values[1]) {
		return nil, fail(400, "asset_category", "资产类别无效")
	}
	args := []any{u.Workspace, u.Role, u.ID, r.PathValue("id")}
	for _, value := range values {
		args = append(args, value)
	}
	args = append(args, ids, limit, offset)
	return a.list(r.Context(), assetSelectSQL, args...)
}

func csvSafe(value any) string {
	text := fmt.Sprint(value)
	trimmed := strings.TrimLeftFunc(text, func(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' || r == 0x200b })
	if strings.ContainsAny(text, "\r\n\t") || strings.HasPrefix(trimmed, "=") || strings.HasPrefix(trimmed, "+") || strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "@") {
		return "'" + text
	}
	return text
}

func (a *App) exportAssets(w http.ResponseWriter, r *http.Request, u *User) error {
	rows, err := a.queryAssets(r, u, 1001, true)
	if err != nil {
		return err
	}
	if len(rows) > 1000 {
		return fail(422, "export_limit", "导出超过 1000 条，请缩小筛选范围；不会静默截断")
	}
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	columns := []string{"id", "name", "category", "kind", "os_family", "environment", "site", "business", "enabled", "archived"}
	if err = writer.Write(columns); err != nil {
		return err
	}
	for _, row := range rows {
		record := make([]string, len(columns))
		for i, key := range columns {
			record[i] = csvSafe(row[key])
		}
		if err = writer.Write(record); err != nil {
			return err
		}
	}
	writer.Flush()
	if err = writer.Error(); err != nil {
		return err
	}
	if err = a.audit(r.Context(), u, "asset.export", "assets", "success", "", map[string]any{"count": len(rows)}); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="infrascope-assets.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, err = w.Write(buffer.Bytes())
	return err
}

func (a *App) assetGroups(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := require(u, "user.manage"); err != nil {
		return err
	}
	ctx := r.Context()
	if r.Method == "GET" {
		offset, err := pageOffset(r.URL.Query().Get("offset"))
		if err != nil {
			return err
		}
		rows, err := a.list(ctx, `SELECT g.id,g.name,g.description,g.enabled,g.starts_at,g.expires_at,g.version,
 COALESCE((SELECT json_agg(asset_id ORDER BY asset_id) FROM ra_asset_group_assets WHERE workspace=g.workspace AND asset_group_id=g.id),'[]') AS asset_ids,
 COALESCE((SELECT json_agg(user_id ORDER BY user_id) FROM ra_asset_group_users WHERE workspace=g.workspace AND asset_group_id=g.id),'[]') AS user_ids,
 COALESCE((SELECT json_agg(group_id ORDER BY group_id) FROM ra_asset_group_subject_groups WHERE workspace=g.workspace AND asset_group_id=g.id),'[]') AS group_ids
 FROM ra_asset_groups g WHERE workspace=$1 ORDER BY name,id LIMIT 100 OFFSET $2`, u.Workspace, offset)
		if err != nil {
			return err
		}
		jsonOut(w, 200, rows)
		return nil
	}
	var in struct {
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Enabled     bool      `json:"enabled"`
		Starts      time.Time `json:"startsAt"`
		Expires     time.Time `json:"expiresAt"`
		Version     int64     `json:"version"`
		AssetIDs    []string  `json:"assetIds"`
		UserIDs     []string  `json:"userIds"`
		GroupIDs    []string  `json:"groupIds"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	in.Name = strings.TrimSpace(in.Name)
	if !bounded(in.Name, 180) || !optionalText(in.Description, 2000) || in.Starts.IsZero() || in.Expires.IsZero() || !in.Expires.After(in.Starts) {
		return fail(400, "asset_group_invalid", "名称、说明或有效期无效")
	}
	var err error
	for _, field := range []struct {
		ids *[]string
		max int
	}{{&in.AssetIDs, 500}, {&in.UserIDs, 100}, {&in.GroupIDs, 100}} {
		*field.ids, err = boundedIDs(*field.ids, field.max)
		if err != nil {
			return err
		}
	}
	id := r.PathValue("id")
	if id != "" && in.Version < 1 {
		return fail(400, "asset_group_version_required", "更新资产组必须携带当前版本")
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if id != "" {
		var version int64
		if err = tx.QueryRow(ctx, "SELECT version FROM ra_asset_groups WHERE workspace=$1 AND id=$2 FOR UPDATE", u.Workspace, id).Scan(&version); errors.Is(err, pgx.ErrNoRows) {
			return fail(404, "asset_group_not_found", "资产组不存在")
		} else if err != nil {
			return err
		}
		if version != in.Version {
			return fail(409, "asset_group_version_conflict", "资产组已被修改，请刷新核对后重试")
		}
	}
	// Query fragments are fixed program constants; client values are always bound parameters.
	for _, refs := range []struct {
		table string
		ids   []string
	}{{"ra_assets", in.AssetIDs}, {"ra_users", in.UserIDs}, {"ra_groups", in.GroupIDs}} {
		for _, reference := range refs.ids {
			var found string
			if err = tx.QueryRow(ctx, "SELECT id FROM "+refs.table+" WHERE workspace=$1 AND id=$2 FOR SHARE", u.Workspace, reference).Scan(&found); errors.Is(err, pgx.ErrNoRows) {
				return fail(400, "asset_group_reference", "范围对象不存在或不属于当前工作空间")
			} else if err != nil {
				return err
			}
		}
	}
	if id == "" {
		id = ID()
		_, err = tx.Exec(ctx, `INSERT INTO ra_asset_groups(id,workspace,name,description,enabled,starts_at,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, u.Workspace, in.Name, in.Description, in.Enabled, in.Starts, in.Expires, u.ID)
	} else {
		_, err = tx.Exec(ctx, `UPDATE ra_asset_groups SET name=$1,description=$2,enabled=$3,starts_at=$4,expires_at=$5,version=version+1,updated_at=now() WHERE workspace=$6 AND id=$7`, in.Name, in.Description, in.Enabled, in.Starts, in.Expires, u.Workspace, id)
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fail(409, "asset_group_name_conflict", "当前工作空间已有同名资产组")
		}
		return err
	}
	for _, refs := range []struct {
		table, column string
		ids           []string
	}{
		{"ra_asset_group_assets", "asset_id", in.AssetIDs}, {"ra_asset_group_users", "user_id", in.UserIDs}, {"ra_asset_group_subject_groups", "group_id", in.GroupIDs},
	} {
		if _, err = tx.Exec(ctx, "DELETE FROM "+refs.table+" WHERE workspace=$1 AND asset_group_id=$2", u.Workspace, id); err != nil {
			return err
		}
		for _, reference := range refs.ids {
			if _, err = tx.Exec(ctx, "INSERT INTO "+refs.table+"(workspace,asset_group_id,"+refs.column+") VALUES($1,$2,$3)", u.Workspace, id, reference); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'asset_group.save',$3,'success',$4)`, u.Workspace, u.ID, id, marshal(map[string]any{"enabled": in.Enabled, "assets": len(in.AssetIDs), "users": len(in.UserIDs), "groups": len(in.GroupIDs), "scope": "asset_metadata_read_only"})); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	jsonOut(w, 200, map[string]string{"id": id})
	return nil
}
