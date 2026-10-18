package access

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Hierarchy is classification, not permission inheritance. This expression is
// only for asset metadata queries, never for remote account or management policy.
const organizationVisibilitySQL = `EXISTS(SELECT 1 FROM ra_organizations org
 JOIN ra_organization_members om ON om.workspace=org.workspace AND om.organization_id=org.id
 WHERE org.workspace=$1 AND org.workspace=a.workspace AND org.id=a.organization_id AND org.enabled AND om.user_id=$3)`

func (a *App) organizationOptions(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := require(u, "asset.manage"); err != nil {
		return err
	}
	offset, err := pageOffset(r.URL.Query().Get("offset"))
	if err != nil {
		return err
	}
	rows, err := a.list(r.Context(), `SELECT o.id,o.name,o.enabled FROM ra_organizations o
 WHERE o.workspace=$1 AND ($2='admin' OR EXISTS(SELECT 1 FROM ra_organization_members m WHERE m.workspace=$1 AND m.organization_id=o.id AND m.user_id=$3))
 ORDER BY o.name,o.id LIMIT 100 OFFSET $4`, u.Workspace, u.Role, u.ID, offset)
	if err != nil {
		return err
	}
	jsonOut(w, 200, rows)
	return nil
}

func (a *App) organizations(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := require(u, "user.manage"); err != nil {
		return err
	}
	ctx := r.Context()
	if r.Method == "GET" {
		offset, err := pageOffset(r.URL.Query().Get("offset"))
		if err != nil {
			return err
		}
		rows, err := a.list(ctx, `SELECT o.id,o.name,o.description,COALESCE(o.parent_id,'') AS parent_id,o.enabled,o.version,
 COALESCE((SELECT json_agg(m.user_id ORDER BY m.user_id) FROM ra_organization_members m WHERE m.workspace=o.workspace AND m.organization_id=o.id),'[]') AS member_ids
 FROM ra_organizations o WHERE o.workspace=$1 ORDER BY o.name,o.id LIMIT 100 OFFSET $2`, u.Workspace, offset)
		if err != nil {
			return err
		}
		jsonOut(w, 200, rows)
		return nil
	}
	var in struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		ParentID    *string  `json:"parentId"`
		Enabled     bool     `json:"enabled"`
		MemberIDs   []string `json:"memberIds"`
		Version     int64    `json:"version"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	in.Name = strings.TrimSpace(in.Name)
	if !bounded(in.Name, 180) || !optionalText(in.Description, 2000) {
		return fail(400, "organization_invalid", "组织名称或说明无效")
	}
	var err error
	in.MemberIDs, err = boundedIDs(in.MemberIDs, 500)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if id != "" && in.Version < 1 {
		return fail(400, "organization_version_required", "更新组织必须携带当前版本")
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize hierarchy edits in a workspace so concurrent reparents cannot
	// independently pass the ancestor check and commit a cycle.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('ra_organizations:'||$1,0))`, u.Workspace); err != nil {
		return err
	}
	parentID := ""
	oldParentID := ""
	if id != "" {
		var version int64
		if err = tx.QueryRow(ctx, `SELECT version,COALESCE(parent_id,'') FROM ra_organizations WHERE workspace=$1 AND id=$2 FOR UPDATE`, u.Workspace, id).Scan(&version, &parentID); errors.Is(err, pgx.ErrNoRows) {
			return fail(404, "organization_not_found", "组织不存在")
		} else if err != nil {
			return err
		}
		if version != in.Version {
			return fail(409, "organization_version_conflict", "组织已被修改，请刷新核对后重试")
		}
		oldParentID = parentID
	}
	if in.ParentID != nil {
		parentID = *in.ParentID
	}
	if parentID != "" {
		if !bounded(parentID, 120) || strings.TrimSpace(parentID) != parentID {
			return fail(400, "organization_parent", "上级组织无效")
		}
		var found string
		if err = tx.QueryRow(ctx, "SELECT id FROM ra_organizations WHERE workspace=$1 AND id=$2", u.Workspace, parentID).Scan(&found); errors.Is(err, pgx.ErrNoRows) {
			return fail(400, "organization_parent", "上级组织不存在或不属于当前工作空间")
		} else if err != nil {
			return err
		}
		var cycle bool
		if err = tx.QueryRow(ctx, `WITH RECURSIVE ancestors(id,parent_id) AS (
 SELECT id,parent_id FROM ra_organizations WHERE workspace=$1 AND id=$2
 UNION SELECT o.id,o.parent_id FROM ra_organizations o JOIN ancestors p ON o.id=p.parent_id WHERE o.workspace=$1
) SELECT EXISTS(SELECT 1 FROM ancestors WHERE id=$3)`, u.Workspace, parentID, id).Scan(&cycle); err != nil {
			return err
		}
		if cycle {
			return fail(400, "organization_cycle", "组织不能指向自身或下级组织")
		}
	}
	for _, memberID := range in.MemberIDs {
		var found string
		if err = tx.QueryRow(ctx, "SELECT id FROM ra_users WHERE workspace=$1 AND id=$2 FOR SHARE", u.Workspace, memberID).Scan(&found); errors.Is(err, pgx.ErrNoRows) {
			return fail(400, "organization_member", "成员必须为当前工作空间的平台用户；联系人不是登录账号")
		} else if err != nil {
			return err
		}
	}
	if id == "" {
		id = ID()
		_, err = tx.Exec(ctx, `INSERT INTO ra_organizations(id,workspace,name,description,parent_id,enabled,created_by) VALUES($1,$2,$3,$4,NULLIF($5,''),$6,$7)`, id, u.Workspace, in.Name, in.Description, parentID, in.Enabled, u.ID)
	} else {
		_, err = tx.Exec(ctx, `UPDATE ra_organizations SET name=$1,description=$2,parent_id=NULLIF($3,''),enabled=$4,version=version+1,updated_at=now() WHERE workspace=$5 AND id=$6`, in.Name, in.Description, parentID, in.Enabled, u.Workspace, id)
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fail(409, "organization_name_conflict", "当前工作空间已有同名组织")
		}
		return err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM ra_organization_members WHERE workspace=$1 AND organization_id=$2", u.Workspace, id); err != nil {
		return err
	}
	for _, memberID := range in.MemberIDs {
		if _, err = tx.Exec(ctx, "INSERT INTO ra_organization_members(workspace,organization_id,user_id) VALUES($1,$2,$3)", u.Workspace, id, memberID); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'organization.save',$3,'success',$4)`, u.Workspace, u.ID, id, marshal(map[string]any{"enabled": in.Enabled, "previousParentId": oldParentID, "parentId": parentID, "memberIds": in.MemberIDs, "scope": "direct_asset_metadata_read_only", "inherits": false})); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	jsonOut(w, 200, map[string]string{"id": id})
	return nil
}

// Call only for an explicitly requested asset organization assignment, inside
// the asset transaction. Existing unmodified assignments must be preserved.
func (a *App) validateAssetOrganization(ctx context.Context, tx pgx.Tx, u *User, id string) error {
	if err := require(u, "asset.manage"); err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	if !bounded(id, 120) || strings.TrimSpace(id) != id {
		return fail(400, "asset_organization", "资产组织无效")
	}
	var enabled bool
	// Organization updates hold FOR UPDATE before changing memberships. Holding
	// FOR SHARE until asset commit prevents concurrent revocation/disable races.
	if err := tx.QueryRow(ctx, "SELECT enabled FROM ra_organizations WHERE workspace=$1 AND id=$2 FOR SHARE", u.Workspace, id).Scan(&enabled); errors.Is(err, pgx.ErrNoRows) {
		return fail(400, "asset_organization", "资产组织不存在或不属于当前工作空间")
	} else if err != nil {
		return err
	}
	if !enabled {
		return fail(400, "asset_organization_disabled", "不能将资产分配到已停用的组织")
	}
	if u.Role != "admin" {
		var member bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ra_organization_members WHERE workspace=$1 AND organization_id=$2 AND user_id=$3)", u.Workspace, id, u.ID).Scan(&member); err != nil {
			return err
		}
		if !member {
			return fail(403, "asset_organization_scope", "只能将资产分配到自己直接所属的组织")
		}
	}
	return nil
}
