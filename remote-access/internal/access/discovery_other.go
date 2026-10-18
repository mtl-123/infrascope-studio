//go:build !linux

package access

func discoverLocalAsset(claimant, organization string) (ImportRow, map[string]any, error) {
	return ImportRow{}, nil, fail(501, "discovery_unsupported", "当前本机发现仅实现 Linux；Windows 与外设实采尚未验证")
}
