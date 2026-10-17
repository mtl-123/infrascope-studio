package access

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"infrascope/remote-access/migrations"
)

type testUser struct {
	client   *http.Client
	csrf, id string
}
type harness struct {
	t                          *testing.T
	a                          *App
	server                     *httptest.Server
	admin                      testUser
	root, asset, account, host string
	port                       int
	signer                     ssh.Signer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db := os.Getenv("INFRA_TEST_DATABASE_URL")
	if db == "" {
		t.Skip("INFRA_TEST_DATABASE_URL not provided; integration suite requires isolated PostgreSQL/PGlite")
	}
	ctx := context.Background()
	c := Config{Enabled: true, LoopbackTest: true, Workspace: ID(), GatewayID: ID(), DatabaseURL: db, Keys: map[string][]byte{"test": make([]byte, 32)}, ActiveKey: "test", Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, SessionHours: 8, MaxSessions: 8, MaxTransfers: 3, Grace: 30, Idle: 120, MaxDuration: 600, RevokePoll: 1, StaticDir: "../../../dist"}
	a, e := New(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if _, e = a.DB.Exec(ctx, migrations.SQL); e != nil {
			t.Fatal("migration", e)
		}
	}
	h := &harness{t: t, a: a, root: t.TempDir()}
	h.server = httptest.NewServer(a.Handler())
	a.Config.Origin = h.server.URL
	h.host, h.port, h.signer = startTarget(t)
	hash, _ := PasswordHash("test-password-123")
	id := ID()
	_, e = a.DB.Exec(ctx, "INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role) VALUES($1,$2,'admin','Admin',$3,'admin')", id, c.Workspace, hash)
	if e != nil {
		t.Fatal(e)
	}
	h.admin = h.login("admin", "test-password-123", 200)
	h.admin.id = id
	t.Cleanup(func() { h.server.Close(); a.Close() })
	return h
}
func (h *harness) request(u testUser, method, url string, body any, want int) map[string]any {
	h.t.Helper()
	var b io.Reader
	if body != nil {
		b = bytes.NewReader(marshal(body))
	}
	r, _ := http.NewRequest(method, h.server.URL+"/api/remote-access"+url, b)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", h.server.URL)
	r.Header.Set("X-CSRF-Token", u.csrf)
	c := u.client
	if c == nil {
		c = http.DefaultClient
	}
	res, e := c.Do(r)
	if e != nil {
		h.t.Fatal(e)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		h.t.Fatalf("%s %s: want %d got %d %s", method, url, want, res.StatusCode, raw)
	}
	out := map[string]any{}
	if len(raw) > 0 && raw[0] == '[' {
		var list []any
		if e = json.Unmarshal(raw, &list); e != nil {
			h.t.Fatal(e)
		}
		out["items"] = list
	} else if e = json.Unmarshal(raw, &out); e != nil {
		h.t.Fatal(e, string(raw))
	}
	return out
}
func (h *harness) login(name, pw string, want int) testUser {
	jar, _ := cookiejar.New(nil)
	u := testUser{client: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
	out := h.request(u, "POST", "/auth/login", map[string]any{"username": name, "password": pw}, want)
	if want == 200 {
		u.csrf = out["csrf"].(string)
		u.id = out["id"].(string)
	}
	return u
}
func (h *harness) user(name, role string) testUser {
	h.t.Helper()
	out := h.request(h.admin, "POST", "/users", map[string]any{"username": name, "displayName": name, "role": role, "initialPassword": "initial-test-123"}, 200)
	u := h.login(name, "initial-test-123", 200)
	h.request(u, "GET", "/assets", nil, 403)
	h.request(u, "POST", "/auth/password", map[string]any{"currentPassword": "initial-test-123", "newPassword": "changed-test-123"}, 200)
	h.request(u, "GET", "/auth/me", nil, 401)
	u = h.login(name, "changed-test-123", 200)
	u.id = out["id"].(string)
	return u
}
func (h *harness) setupAsset() {
	h.t.Helper()
	eps := []map[string]any{}
	for _, proto := range []string{"ssh", "sftp", "rdp"} {
		eps = append(eps, map[string]any{"protocol": proto, "host": h.host, "port": h.port, "gatewayId": h.a.Config.GatewayID})
	}
	v := h.request(h.admin, "POST", "/assets", map[string]any{"name": "Integration target", "kind": "virtual", "osFamily": "linux", "groupName": "isolated-tests", "tags": []string{}, "metadata": map[string]string{}, "enabled": true, "endpoints": eps}, 200)
	h.asset = v["id"].(string)
	v = h.request(h.admin, "POST", "/assets/"+h.asset+"/accounts", map[string]any{"name": "test-os-account", "username": "tester", "authType": "password", "protocols": []string{"ssh", "sftp", "rdp"}, "enabled": true}, 200)
	h.account = v["id"].(string)
	h.request(h.admin, "POST", "/accounts/"+h.account+"/credential", map[string]any{"action": "set", "secret": map[string]string{"password": "remote-test-secret"}}, 200)
}
func (h *harness) trust() {
	for _, proto := range []string{"ssh", "sftp"} {
		p := h.request(h.admin, "POST", "/assets/"+h.asset+"/host-key/probe", map[string]any{"protocol": proto}, 200)
		if p["fingerprint"] != ssh.FingerprintSHA256(h.signer.PublicKey()) {
			h.t.Fatal("probe fingerprint")
		}
		h.request(h.admin, "POST", "/assets/"+h.asset+"/host-key/approve", map[string]any{"protocol": proto, "fingerprint": p["fingerprint"], "algorithm": p["algorithm"], "confirm": true}, 200)
	}
}
func (h *harness) grant(u testUser, readonly bool) string {
	acts := []string{"remoteAccount.use", "asset.view", "remoteAccount.view", "ssh.connect", "ssh.resume", "ssh.close", "sftp.list", "sftp.download", "rdp.launch"}
	if !readonly {
		acts = append(acts, "sftp.upload", "sftp.mkdir", "sftp.rename", "sftp.delete", "rdp.clipboard", "rdp.driveRedirect")
	}
	v := h.request(h.admin, "POST", "/grants", map[string]any{"userId": u.id, "assetId": h.asset, "accountId": h.account, "actions": acts, "protocols": []string{"ssh", "sftp", "rdp"}, "startsAt": time.Now().Add(-time.Minute), "expiresAt": time.Now().Add(time.Hour), "limits": Limits{ReadRoots: []string{h.root}, WriteRoots: []string{h.root}, MaxFileBytes: 10 << 20, MaxTotalBytes: 100 << 20, MaxFiles: 1000, MaxDepth: 20, MaxConcurrent: 3, AllowOverwrite: !readonly}}, 200)
	return v["id"].(string)
}
func (h *harness) attach(u testUser, id, window string, last uint64) (*websocket.Conn, int64) {
	h.t.Helper()
	v := h.request(u, "POST", "/ssh/sessions/"+id+"/attach-authorizations", map[string]string{"windowId": window}, 200)
	hdr := http.Header{"Origin": []string{h.server.URL}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, e := websocket.Dial(ctx, "ws"+strings.TrimPrefix(h.server.URL, "http")+"/api/remote-access/ssh/sessions/"+id+"/stream", &websocket.DialOptions{HTTPClient: u.client, HTTPHeader: hdr})
	if e != nil {
		h.t.Fatal(e)
	}
	e = ws.Write(ctx, websocket.MessageText, marshal(map[string]any{"type": "attach", "authorization": v["authorization"], "lastSequence": last}))
	if e != nil {
		h.t.Fatal(e)
	}
	_, b, e := ws.Read(ctx)
	if e != nil {
		h.t.Fatal(e)
	}
	var state map[string]any
	json.Unmarshal(b, &state)
	if state["state"] != "ready" {
		h.t.Fatalf("attach: %s", b)
	}
	return ws, int64(state["lease"].(float64))
}
func startTarget(t *testing.T) (string, int, ssh.Signer) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() != "tester" || string(password) != "remote-test-secret" {
			return nil, fmt.Errorf("denied")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				sc, chans, reqs, e := ssh.NewServerConn(conn, cfg)
				if e != nil {
					conn.Close()
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "session" {
						ch.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					channel, requests, e := ch.Accept()
					if e != nil {
						return
					}
					go targetSession(channel, requests)
				}
			}()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, signer
}
func targetSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	defer ch.Close()
	var master, slave *os.File
	var cmd *exec.Cmd
	for req := range requests {
		switch req.Type {
		case "subsystem":
			var q struct{ Name string }
			ssh.Unmarshal(req.Payload, &q)
			if q.Name != "sftp" {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			server, e := sftp.NewServer(ch)
			if e == nil {
				_ = server.Serve()
				server.Close()
			}
			return
		case "pty-req":
			var q struct {
				Term                      string
				Cols, Rows, Width, Height uint32
				Modes                     string
			}
			ssh.Unmarshal(req.Payload, &q)
			var e error
			master, e = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0600)
			if e == nil {
				e = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0)
			}
			if e != nil {
				req.Reply(false, nil)
				continue
			}
			n, e := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
			if e == nil {
				slave, e = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0600)
			}
			if e != nil {
				master.Close()
				req.Reply(false, nil)
				continue
			}
			unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(q.Rows), Col: uint16(q.Cols)})
			req.Reply(true, nil)
		case "shell":
			if master == nil {
				req.Reply(false, nil)
				continue
			}
			cmd = exec.Command("/bin/sh")
			cmd.Env = append(os.Environ(), "TERM=xterm-256color")
			cmd.Stdin = slave
			cmd.Stdout = slave
			cmd.Stderr = slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if e := cmd.Start(); e != nil {
				req.Reply(false, nil)
				continue
			}
			slave.Close()
			req.Reply(true, nil)
			go io.Copy(master, ch)
			go func() { io.Copy(ch, master); ch.Close() }()
			go func() {
				cmd.Wait()
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				master.Close()
				ch.Close()
			}()
		case "window-change":
			var q struct{ Cols, Rows, Width, Height uint32 }
			ssh.Unmarshal(req.Payload, &q)
			if master != nil {
				unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(q.Rows), Col: uint16(q.Cols)})
			}
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
	}
	if master != nil {
		master.Close()
	}
}
func TestIntegrationIdentitySSHAndRevocation(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	alice := h.user("alice", "operator")
	bob := h.user("bob", "operator")
	carol := h.user("carol", "operator")
	h.grant(alice, false)
	h.grant(bob, true)
	h.grant(carol, false)
	h.request(alice, "POST", "/users", map[string]string{}, 403)
	h.request(alice, "POST", "/ssh/sessions", map[string]any{"assetId": h.asset, "accountId": h.account, "cols": 100, "rows": 30}, 409)
	h.trust()
	h.request(h.admin, "POST", "/accounts/"+h.account+"/test", map[string]string{"protocol": "sftp"}, 200)
	if e := h.a.StartBackground(context.Background()); e != nil {
		t.Fatal(e)
	}
	sessions := map[string]string{}
	for i, u := range []testUser{alice, bob, carol} {
		for j := 0; j < 2; j++ {
			v := h.request(u, "POST", "/ssh/sessions", map[string]any{"assetId": h.asset, "accountId": h.account, "cols": 100, "rows": 30}, 201)
			sessions[fmt.Sprintf("%d-%d", i, j)] = v["id"].(string)
		}
	}
	id := sessions["0-0"]
	h.request(bob, "GET", "/ssh/sessions/"+id, nil, 404)
	ws, lease := h.attach(alice, id, "window-1", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if e := ws.Write(ctx, websocket.MessageText, marshal(map[string]any{"type": "input", "sequence": 1, "lease": lease, "data": "printf 'actual-pty-output\\n'; stty size\n"})); e != nil {
		t.Fatal(e)
	}
	output := ""
	var last uint64
	for !strings.Contains(output, "30 100") {
		_, b, e := ws.Read(ctx)
		if e != nil {
			t.Fatal(e, output)
		}
		var m map[string]any
		json.Unmarshal(b, &m)
		if m["type"] == "output" {
			raw, _ := base64.StdEncoding.DecodeString(m["data"].(string))
			output += string(raw)
			last = uint64(m["sequence"].(float64))
		}
	}
	if !strings.Contains(output, "actual-pty-output") {
		t.Fatal(output)
	}
	ws2, lease2 := h.attach(alice, id, "window-2", last)
	if lease2 <= lease {
		t.Fatal("lease did not advance")
	}
	ws.CloseNow()
	defer ws2.CloseNow()
	h.request(h.admin, "PATCH", "/users/"+alice.id, map[string]any{"enabled": false}, 200)
	h.request(alice, "GET", "/auth/me", nil, 401)
	time.Sleep(1200 * time.Millisecond)
	h.a.mu.Lock()
	session := h.a.sessions[id]
	h.a.mu.Unlock()
	if session != nil {
		session.mu.Lock()
		state := session.state
		session.mu.Unlock()
		if state != "closed" {
			t.Fatal("revocation did not close session")
		}
	}
	h.request(bob, "POST", "/transfers", map[string]any{"accountId": h.account, "direction": "upload", "target": h.root, "conflict": "ask"}, 403)
}
func TestIntegrationSFTPIntegrity(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	h.trust()
	alice := h.user("file-user", "operator")
	bob := h.user("other-user", "operator")
	h.grant(alice, false)
	h.grant(bob, false)
	h.request(alice, "GET", "/sftp/entries?accountId="+h.account+"&path=/etc", nil, 403)
	out := h.request(alice, "POST", "/transfers", map[string]any{"accountId": h.account, "direction": "upload", "target": h.root, "conflict": "ask"}, 201)
	id := out["id"].(string)
	contents := []byte("实际 SFTP 文件内容\x00\n" + strings.Repeat("x", 131000))
	sum := sha256.Sum256(contents)
	h.request(alice, "POST", "/transfers/"+id+"/items", map[string]any{"items": []ManifestItem{{Path: "中文目录", Directory: true}, {Path: "中文目录/空文件"}, {Path: "中文目录/empty", Directory: true}, {Path: "中文目录/数据.bin", Size: int64(len(contents)), SHA: hex.EncodeToString(sum[:])}}, "final": true}, 200)
	h.request(bob, "GET", "/transfers/"+id, nil, 404)
	task := h.request(alice, "GET", "/transfers/"+id, nil, 200)
	for _, v := range task["items"].([]any) {
		item := v.(map[string]any)
		body := []byte{}
		if item["size"].(float64) > 0 {
			body = contents
		}
		h.chunk(alice, id, item["id"].(string), body, 0, 200)
	}
	result := h.request(alice, "POST", "/transfers/"+id+"/commit", map[string]any{}, 200)
	if result["state"] != "completed" {
		t.Fatal(result)
	}
	actual, e := os.ReadFile(filepath.Join(h.root, "中文目录", "数据.bin"))
	if e != nil || !bytes.Equal(actual, contents) {
		t.Fatal("actual remote hash mismatch", e)
	}
	out = h.request(alice, "POST", "/transfers", map[string]any{"accountId": h.account, "direction": "download", "target": h.root, "conflict": "ask", "paths": []string{"中文目录"}}, 201)
	downloadID := out["id"].(string)
	res, e := alice.client.Get(h.server.URL + "/api/remote-access/transfers/" + downloadID + "/content")
	if e != nil {
		t.Fatal(e)
	}
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, string(data))
	}
	z, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	found := map[string]bool{}
	for _, f := range z.File {
		found[f.Name] = true
		if f.Name == "中文目录/数据.bin" {
			r, _ := f.Open()
			b, _ := io.ReadAll(r)
			r.Close()
			if !bytes.Equal(b, contents) {
				t.Fatal("archive integrity")
			}
		}
	}
	for _, name := range []string{"中文目录/", "中文目录/empty/", "中文目录/空文件", "中文目录/数据.bin"} {
		if !found[name] {
			t.Fatal("missing archive member", name)
		}
	}
	h.request(alice, "POST", "/sftp/rename", map[string]any{"accountId": h.account, "path": filepath.Join(h.root, "中文目录", "数据.bin"), "destination": filepath.Join(h.root, "中文目录", "renamed.bin")}, 200)
	h.request(alice, "POST", "/sftp/delete", map[string]any{"accountId": h.account, "path": filepath.Join(h.root, "中文目录"), "recursive": true, "confirm": true}, 200)
	if _, e = os.Stat(filepath.Join(h.root, "中文目录")); !os.IsNotExist(e) {
		t.Fatal("recursive delete failed")
	}
}
func (h *harness) chunk(u testUser, task, item string, body []byte, offset int64, want int) {
	h.t.Helper()
	sum := sha256.Sum256(body)
	r, _ := http.NewRequest("PUT", h.server.URL+"/api/remote-access/transfers/"+task+"/items/"+item+"/content", bytes.NewReader(body))
	r.Header.Set("Origin", h.server.URL)
	r.Header.Set("X-CSRF-Token", u.csrf)
	r.Header.Set("Upload-Offset", strconv.FormatInt(offset, 10))
	r.Header.Set("Upload-SHA256", hex.EncodeToString(sum[:]))
	res, e := u.client.Do(r)
	if e != nil {
		h.t.Fatal(e)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != want {
		h.t.Fatalf("chunk %s: %d %s", item, res.StatusCode, b)
	}
}
func TestIntegrationRDPDeviceProtocol(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	u := h.user("rdp-user", "operator")
	h.grant(u, false)
	p := h.request(u, "POST", "/connectors/pairing-challenges", map[string]any{}, 201)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sid := digest("test-windows-user")
	proof := ed25519.Sign(key, []byte("pair\n"+p["challenge"].(string)+"\n"+h.server.URL+"\n"+sid))
	payload := map[string]any{"challenge": p["challenge"], "publicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "name": "Protocol test device (not Windows)", "windowsUserHash": sid, "version": "test", "signature": base64.StdEncoding.EncodeToString(proof), "origin": h.server.URL}
	paired := h.request(testUser{}, "POST", "/connector/pair", payload, 201)
	h.request(testUser{}, "POST", "/connector/pair", payload, 410)
	device := paired["connectorId"].(string)
	binding := paired["browserBindingId"].(string)
	h.device(device, key, "poll", map[string]any{"capabilities": map[string]any{}, "windowsUserHash": sid}, 200, "")
	launch := h.request(u, "POST", "/rdp/launches", map[string]any{"assetId": h.asset, "accountId": h.account, "connectorId": device, "browserBindingId": binding, "options": RDPOptions{DriveMode: "all", Fullscreen: true}, "idempotencyKey": ID()}, 201)
	id := launch["id"].(string)
	nonce := ID()
	redeemed := h.device(device, key, "redeem", map[string]any{"launchId": id, "locallyConfirmed": true}, 200, nonce)
	if redeemed["password"] != "remote-test-secret" {
		t.Fatal("device credential delivery")
	}
	h.device(device, key, "redeem", map[string]any{"launchId": id, "locallyConfirmed": true}, 409, nonce)
	h.device(device, key, "redeem", map[string]any{"launchId": id, "locallyConfirmed": true}, 410, "")
	h.request(u, "POST", "/connectors/"+device+"/revoke", map[string]any{}, 200)
	h.device(device, key, "poll", map[string]any{}, 403, "")
}
func (h *harness) device(device string, key ed25519.PrivateKey, op string, data any, want int, nonce string) map[string]any {
	h.t.Helper()
	if nonce == "" {
		nonce = ID()
	}
	route := "/api/remote-access/connector/" + op
	body := marshal(data)
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := ed25519.Sign(key, []byte("POST\n"+route+"\n"+stamp+"\n"+nonce+"\n"+digest(string(body))))
	r, _ := http.NewRequest("POST", h.server.URL+route, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Connector-Id", device)
	r.Header.Set("X-Connector-Time", stamp)
	r.Header.Set("X-Connector-Nonce", nonce)
	r.Header.Set("X-Connector-Signature", base64.StdEncoding.EncodeToString(sig))
	res, e := http.DefaultClient.Do(r)
	if e != nil {
		h.t.Fatal(e)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		h.t.Fatalf("device %s: want%d got%d %s", op, want, res.StatusCode, b)
	}
	out := map[string]any{}
	json.Unmarshal(b, &out)
	return out
}

func TestIntegrationResumeAndConflict(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	h.trust()
	u := h.user("resume-user", "operator")
	grant := h.grant(u, false)
	v := h.request(u, "POST", "/transfers", map[string]any{"accountId": h.account, "direction": "upload", "target": h.root, "conflict": "ask"}, 201)
	id := v["id"].(string)
	data := bytes.Repeat([]byte("resume-content-"), 10000)
	h.request(u, "POST", "/transfers/"+id+"/items", map[string]any{"items": []ManifestItem{{Path: "resume.bin", Size: int64(len(data))}}, "final": true}, 200)
	task := h.request(u, "GET", "/transfers/"+id, nil, 200)
	item := task["items"].([]any)[0].(map[string]any)["id"].(string)
	h.chunk(u, id, item, data[:65536], 0, 200)
	h.chunk(u, id, item, data[:65536], 0, 200)
	task = h.request(u, "GET", "/transfers/"+id, nil, 200)
	chunks := task["items"].([]any)[0].(map[string]any)["chunks"].([]any)
	prefixHash := sha256.Sum256(data[:65536])
	if len(chunks) != 1 || chunks[0].(map[string]any)["size"] != float64(65536) || chunks[0].(map[string]any)["sha256"] != hex.EncodeToString(prefixHash[:]) {
		t.Fatal("resume metadata must describe the confirmed prefix exactly")
	}
	h.request(u, "POST", "/transfers/"+id+"/control", map[string]any{"action": "pause"}, 200)
	var temp string
	if e := h.a.DB.QueryRow(context.Background(), "SELECT temp_path FROM ra_transfer_items WHERE id=$1", item).Scan(&temp); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(temp, bytes.Repeat([]byte("!"), 65536), 0600); e != nil {
		t.Fatal(e)
	}
	h.chunk(u, id, item, data[65536:], 65536, 409)
	if e := os.WriteFile(temp, data[:65536], 0600); e != nil {
		t.Fatal(e)
	}
	h.chunk(u, id, item, data[65536:], 65536, 200)
	if e := os.WriteFile(filepath.Join(h.root, "resume.bin"), []byte("existing"), 0600); e != nil {
		t.Fatal(e)
	}
	out := h.request(u, "POST", "/transfers/"+id+"/commit", map[string]any{}, 200)
	if out["state"] != "partial" {
		t.Fatal(out)
	}
	h.request(u, "POST", "/transfers/"+id+"/control", map[string]any{"action": "retry", "conflict": "rename"}, 200)
	out = h.request(u, "POST", "/transfers/"+id+"/commit", map[string]any{}, 200)
	if out["state"] != "completed" {
		t.Fatal(out)
	}
	original, _ := os.ReadFile(filepath.Join(h.root, "resume.bin"))
	if string(original) != "existing" {
		t.Fatal("overwrote existing file")
	}
	actual, e := os.ReadFile(filepath.Join(h.root, "resume ("+item[:8]+").bin"))
	if e != nil || !bytes.Equal(actual, data) {
		t.Fatal("resume integrity", e)
	}
	os.Symlink("/etc", filepath.Join(h.root, "escape"))
	h.request(u, "GET", "/sftp/entries?accountId="+h.account+"&path="+filepath.Join(h.root, "escape"), nil, 403)
	h.request(h.admin, "DELETE", "/grants/"+grant, nil, 200)
	h.request(u, "GET", "/sftp/entries?accountId="+h.account+"&path="+h.root, nil, 403)
}
func TestIntegrationWorkspaceAndGroupScope(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	h.trust()
	u := h.user("group-user", "operator")
	other := h.user("no-grant", "operator")
	h.request(other, "GET", "/accounts/"+h.account, nil, 404)
	v := h.request(h.admin, "POST", "/groups", map[string]any{"name": "operations", "members": []string{u.id}}, 200)
	group := v["id"].(string)
	g := h.request(h.admin, "POST", "/grants", map[string]any{"groupId": group, "assetId": h.asset, "accountId": h.account, "actions": []string{"remoteAccount.use", "sftp.list", "sftp.download"}, "protocols": []string{"sftp"}, "startsAt": time.Now().Add(-time.Minute), "expiresAt": time.Now().Add(time.Hour), "limits": Limits{ReadRoots: []string{h.root}, MaxFileBytes: 1 << 20, MaxTotalBytes: 10 << 20, MaxFiles: 100, MaxDepth: 10, MaxConcurrent: 1}}, 200)
	h.request(u, "GET", "/sftp/entries?accountId="+h.account+"&path="+h.root, nil, 200)
	h.request(u, "POST", "/sftp/delete", map[string]any{"accountId": h.account, "path": h.root, "confirm": true}, 403)
	h.request(h.admin, "PATCH", "/groups/"+group, map[string]any{"name": "operations", "members": []string{}}, 200)
	h.request(u, "GET", "/sftp/entries?accountId="+h.account+"&path="+h.root, nil, 403)
	if _, e := h.a.DB.Exec(context.Background(), "UPDATE ra_grants SET expires_at=now()-interval '1 second',starts_at=now()-interval '2 hours' WHERE id=$1", g["id"]); e != nil {
		t.Fatal(e)
	}
	hash, _ := PasswordHash("cross-workspace-test")
	id := ID()
	if _, e := h.a.DB.Exec(context.Background(), "INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role) VALUES($1,'another-workspace','other','Other',$2,'operator')", id, hash); e != nil {
		t.Fatal(e)
	}
	token := ID()
	csrf := ID()
	if _, e := h.a.DB.Exec(context.Background(), "INSERT INTO ra_login_sessions(id_hash,workspace,user_id,auth_version,csrf,expires_at) VALUES($1,'another-workspace',$2,1,$3,now()+interval '1 hour')", digest(token), id, csrf); e != nil {
		t.Fatal(e)
	}
	jar, _ := cookiejar.New(nil)
	uri, _ := url.Parse(h.server.URL)
	jar.SetCookies(uri, []*http.Cookie{{Name: "infra_session", Value: token, Path: "/"}})
	cross := testUser{client: &http.Client{Jar: jar}, csrf: csrf, id: id}
	h.request(cross, "GET", "/accounts/"+h.account, nil, 404)
	h.request(cross, "GET", "/assets/"+h.asset, nil, 404)
	if _, e := h.a.DB.Exec(context.Background(), `INSERT INTO ra_assets(id,workspace,name,kind,os_family,created_by) SELECT $1||'-page-'||i::text,$2,'pagination-'||lpad(i::text,3,'0'),'virtual','linux',$3 FROM generate_series(1,105) i`, h.asset, h.a.Config.Workspace, h.admin.id); e != nil {
		t.Fatal(e)
	}
	first := h.request(h.admin, "GET", "/assets?q=pagination-&offset=0", nil, 200)["items"].([]any)
	second := h.request(h.admin, "GET", "/assets?q=pagination-&offset=100", nil, 200)["items"].([]any)
	if len(first) != 100 || len(second) != 5 || first[99].(map[string]any)["name"] == second[0].(map[string]any)["name"] {
		t.Fatal("asset search pagination does not cover distinct pages")
	}
	if len(h.request(cross, "GET", "/assets?q=pagination-", nil, 200)["items"].([]any)) != 0 {
		t.Fatal("asset search crossed workspace boundary")
	}
	h.request(h.admin, "GET", "/assets?offset=invalid", nil, 400)
	h.a.Config.Keys["next"] = bytes.Repeat([]byte{7}, 32)
	h.a.Config.ActiveKey = "next"
	if e := h.a.RotateKeys(context.Background()); e != nil {
		t.Fatal(e)
	}
	x, e := h.a.account(context.Background(), &User{Workspace: h.a.Config.Workspace}, h.account)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := h.a.secret(context.Background(), &User{Workspace: h.a.Config.Workspace}, x)
	if e != nil || secret.Password != "remote-test-secret" {
		t.Fatal("key rotation integrity")
	}
}
