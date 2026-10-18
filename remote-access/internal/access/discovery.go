package access

import (
	"net/http"
	"time"
)

func (a *App) previewLocalDiscovery(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := require(u, "asset.manage"); err != nil {
		return err
	}
	var in struct {
		Claimant     string `json:"claimantId"`
		Organization string `json:"organizationId"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if !a.rate("local-discovery:"+u.ID, 5, time.Minute) {
		return fail(429, "discovery_limit", "本机发现过于频繁，请稍后重试")
	}
	row, facts, err := discoverLocalAsset(in.Claimant, in.Organization)
	if err != nil {
		return err
	}
	return a.createImportPreview(w, r, u, "local_discovery", in.Claimant, in.Organization, []ImportRow{row}, facts)
}
