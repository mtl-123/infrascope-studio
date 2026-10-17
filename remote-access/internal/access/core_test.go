package access

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCredentialsAndPassword(t *testing.T) {
	h, e := PasswordHash("a-long-test-password")
	if e != nil || !passwordOK(h, "a-long-test-password") || passwordOK(h, "wrong") {
		t.Fatal("password verification")
	}
	key := make([]byte, 32)
	key[0] = 9
	ct, nonce, e := seal(key, "w:a:1", Secret{Password: " secret "})
	if e != nil {
		t.Fatal(e)
	}
	var s Secret
	if e = unseal(key, nonce, ct, "w:a:1", &s); e != nil || s.Password != " secret " {
		t.Fatal("decrypt")
	}
	if unseal(key, nonce, ct, "w:b:1", &s) == nil {
		t.Fatal("AAD cross account accepted")
	}
	ct[0] ^= 1
	if unseal(key, nonce, ct, "w:a:1", &s) == nil {
		t.Fatal("tamper accepted")
	}
	b, _ := json.Marshal(User{LoginHash: "secret", CSRF: "csrf-secret"})
	if strings.Contains(string(b), "secret") {
		t.Fatal("auth fields leaked")
	}
}
func TestPathsAndRDP(t *testing.T) {
	for _, s := range []string{"../a", "a/../../b", "/etc/passwd", "x\\y", "x//y", "a/./b", "a:\\file", "a\x00b"} {
		if safeRelative(s) {
			t.Fatalf("unsafe %q", s)
		}
	}
	for _, s := range []string{"目录/空.txt", "a b/c", "zero"} {
		if !safeRelative(s) {
			t.Fatal(s)
		}
	}
	if within("/safe2/a", "/safe") || !within("/safe/a", "/safe") {
		t.Fatal("root boundary")
	}
	d, e := normalizeDrives(" c:,D:\\;c:\\")
	if e != nil || d != "C:\\;D:\\" {
		t.Fatalf("drives %q %v", d, e)
	}
	for _, s := range []string{"C:\\Windows", "\\\\server\\share", "C", ""} {
		if _, e = normalizeDrives(s); e == nil {
			t.Fatal("drive accepted", s)
		}
	}
	if _, e = validateOptions(RDPOptions{Clipboard: true, DriveMode: "all"}, Policy{}); e == nil {
		t.Fatal("clipboard bypass")
	}
}
func TestStrictJSON(t *testing.T) {
	for _, body := range []string{`{"name":"x","unknown":1}`, `{"name":true}`, `{"name":"x"}{"name":"y"}`} {
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		var in struct {
			Name string `json:"name"`
		}
		if decode(httptest.NewRecorder(), req, &in) == nil {
			t.Fatal("accepted invalid schema", body)
		}
	}
}
