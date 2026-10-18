package access

import (
	"context"
	"net/netip"
)

// Per-asset permissions never authorize another endpoint, port or later edit.
func (a *App) exactEndpointPermit(ctx context.Context, endpoint Endpoint) (bool, error) {
	if a.DB == nil || endpoint.ID == "" {
		return false, nil
	}
	if _, err := netip.ParseAddr(endpoint.Host); err != nil {
		return false, nil
	}
	var permitted bool
	err := a.store(ctx).QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM ra_asset_egress p JOIN ra_endpoints e ON e.workspace=p.workspace AND e.asset_id=p.asset_id AND e.protocol=p.protocol
 JOIN ra_assets a ON a.workspace=e.workspace AND a.id=e.asset_id
 WHERE e.id=$1 AND e.host=$2 AND e.port=$3 AND e.gateway_id=$4 AND e.protocol=$5 AND p.host=e.host AND p.port=e.port
 AND a.enabled AND NOT a.archived)`, endpoint.ID, endpoint.Host, endpoint.Port, endpoint.Gateway, endpoint.Protocol).Scan(&permitted)
	return permitted, err
}
