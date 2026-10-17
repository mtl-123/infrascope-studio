package access

import (
	"context"
	"time"
)

func (a *App) maintainGatewayLease(ctx context.Context) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			check, cancel := context.WithTimeout(ctx, 3*time.Second)
			res, e := a.DB.Exec(check, "UPDATE ra_gateway_leases SET expires_at=now()+interval '30 seconds' WHERE gateway_id=$1 AND instance_id=$2 AND expires_at>now()", a.Config.GatewayID, a.instanceID)
			cancel()
			if e == nil && res.RowsAffected() == 1 {
				continue
			}
			a.leaseLost.Store(true)
			a.mu.Lock()
			var list []*SSHSession
			for _, s := range a.sessions {
				list = append(list, s)
			}
			a.mu.Unlock()
			for _, s := range list {
				s.terminate("gateway_lease_lost")
			}
			if a.cancel != nil {
				a.cancel()
			}
			return
		}
	}
}
