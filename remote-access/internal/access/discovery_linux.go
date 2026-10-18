package access

import (
	"bufio"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func discoverLocalAsset(claimant, organization string) (ImportRow, map[string]any, error) {
	name, err := os.Hostname()
	if err != nil || !bounded(name, 180) {
		return ImportRow{}, nil, fail(503, "discovery_hostname", "无法读取本机主机名")
	}
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil || strings.TrimSpace(string(machineID)) == "" {
		return ImportRow{}, nil, fail(503, "discovery_identity", "无法取得本机稳定身份；不会用 IP 冒充唯一设备标识")
	}
	// Keep the local machine identifier out of API/log payloads.
	identity := "local-linux-" + digest(strings.TrimSpace(string(machineID)))
	osRelease, _ := os.ReadFile("/etc/os-release")
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	if !strings.Contains(strings.ToLower(string(kernel)), "microsoft") {
		return ImportRow{}, nil, fail(501, "discovery_classification_unverified", "本轮本机发现仅验证 WSL Linux；其他 Linux 的物理/虚拟分类需适配验证，不能猜测登记")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return ImportRow{}, nil, fail(503, "discovery_interfaces", "无法枚举本机网络接口")
	}
	interfaceFacts := []map[string]any{}
	for _, iface := range interfaces {
		addresses, addressErr := iface.Addrs()
		ips := []string{}
		for _, address := range addresses {
			ips = append(ips, address.String())
		}
		sort.Strings(ips)
		state := "available"
		if addressErr != nil {
			state = "unavailable"
		}
		interfaceFacts = append(interfaceFacts, map[string]any{"index": iface.Index, "name": iface.Name, "mac": iface.HardwareAddr.String(), "mtu": iface.MTU, "flags": iface.Flags.String(), "addresses": ips, "addressState": state})
	}
	sort.Slice(interfaceFacts, func(i, j int) bool { return interfaceFacts[i]["index"].(int) < interfaceFacts[j]["index"].(int) })
	mounts := []map[string]any{}
	file, mountErr := os.Open("/proc/self/mounts")
	truncated := false
	if mountErr == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			parts := strings.Fields(scanner.Text())
			if len(parts) < 3 {
				continue
			}
			if contains([]string{"proc", "sysfs", "cgroup2", "devpts", "tmpfs", "devtmpfs", "securityfs", "debugfs", "tracefs", "fusectl", "mqueue", "hugetlbfs", "pstore", "binfmt_misc"}, parts[2]) {
				continue
			}
			if len(mounts) == 128 {
				truncated = true
				break
			}
			point := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\134", "\\").Replace(parts[1])
			if !strings.HasPrefix(point, "/") {
				continue
			}
			mount := map[string]any{"path": point, "type": parts[2], "state": "available"}
			var stat unix.Statfs_t
			if e := unix.Statfs(point, &stat); e != nil {
				mount["state"] = "unavailable"
			} else {
				mount["totalBytes"] = strconv.FormatUint(stat.Blocks*uint64(stat.Bsize), 10)
				mount["availableBytes"] = strconv.FormatUint(stat.Bavail*uint64(stat.Bsize), 10)
			}
			mounts = append(mounts, mount)
		}
		mountErr = scanner.Err()
	}
	mountState := "available"
	if mountErr != nil {
		mountState = "partial"
	}
	facts := map[string]any{"hostname": name, "osRelease": string(osRelease), "kernel": strings.TrimSpace(string(kernel)), "interfaces": interfaceFacts, "mounts": mounts, "mountState": mountState, "mountsTruncated": truncated, "observedAt": time.Now().UTC().Format(time.RFC3339Nano), "observer": "platform_local_linux", "boundary": "Only the Linux host running this Go service; not Rust Agent, Windows, or network scanning", "identitySource": "sha256(/etc/machine-id)"}
	category := "server"
	payload := AssetInput{Name: name, Inventory: identity, Category: &category, Kind: "virtual", OS: "linux", Description: "平台所在 Linux 的本机只读发现；必须人工确认，不推断运行服务或远程能力", Enabled: true, Tags: []string{}, Metadata: map[string]string{}, Endpoints: []Endpoint{}, OrganizationID: &organization, Ownership: &Ownership{State: "pending", ClaimantID: claimant, NotificationIDs: []string{}, BackupIDs: []string{}}}
	facts["virtualization"] = "wsl"
	return ImportRow{RowNumber: 1, InventoryID: identity, Name: name, State: "ready", Message: "本机事实已读取，待确认登记；尚未安装采集 Agent", Payload: payload}, facts, nil
}
