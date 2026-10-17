package access

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
)

// RotateKeys re-encrypts secrets under the active injected master key. It never changes OS passwords.
func (a *App) RotateKeys(ctx context.Context) error {
	for {
		tx, e := a.DB.Begin(ctx)
		if e != nil {
			return e
		}
		var workspace, account, old string
		var version int64
		var nonce, ct []byte
		e = tx.QueryRow(ctx, "SELECT workspace,account_id,key_version,version,nonce,ciphertext FROM ra_secrets WHERE key_version<>$1 ORDER BY account_id LIMIT 1 FOR UPDATE", a.Config.ActiveKey).Scan(&workspace, &account, &old, &version, &nonce, &ct)
		if e != nil {
			tx.Rollback(ctx)
			if errors.Is(e, pgx.ErrNoRows) {
				return nil
			}
			return e
		}
		var secret Secret
		aad := fmt.Sprintf("%s:%s:%d", workspace, account, version)
		e = unseal(a.Config.Keys[old], nonce, ct, aad, &secret)
		if e != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("old master key unavailable or ciphertext integrity invalid")
		}
		encrypted, newNonce, e := seal(a.Config.Keys[a.Config.ActiveKey], aad, secret)
		secret = Secret{}
		if e == nil {
			_, e = tx.Exec(ctx, "UPDATE ra_secrets SET ciphertext=$1,nonce=$2,key_version=$3,updated_at=now() WHERE account_id=$4", encrypted, newNonce, a.Config.ActiveKey, account)
		}
		if e == nil {
			_, e = tx.Exec(ctx, "INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,'system','credential.master_key_rotate',$2,'success',$3)", workspace, account, marshal(map[string]string{"keyVersion": a.Config.ActiveKey}))
		}
		if e != nil {
			tx.Rollback(ctx)
			return e
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
	}
}
