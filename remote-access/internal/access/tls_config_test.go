package access

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tlsConfigFixture(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert, privateKey := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(privateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	return cert, privateKey
}

func TestNativeTLSConfig(t *testing.T) {
	cert, key := tlsConfigFixture(t)
	for _, tc := range []struct {
		name, cert, key, origin, redirect, wantError string
	}{
		{name: "native HTTPS", cert: cert, key: key, origin: "https://127.0.0.1:18443", redirect: "127.0.0.1:18080"},
		{name: "reverse proxy HTTPS", origin: "https://infrascope.example"},
		{name: "certificate without key", cert: cert, origin: "https://127.0.0.1:18443", wantError: "configured together"},
		{name: "key without certificate", key: key, origin: "https://127.0.0.1:18443", wantError: "configured together"},
		{name: "invalid certificate", cert: key, key: key, origin: "https://127.0.0.1:18443", wantError: "load server TLS"},
		{name: "missing certificate", cert: cert + ".missing", key: key, origin: "https://127.0.0.1:18443", wantError: "load server TLS"},
		{name: "TLS with HTTP origin", cert: cert, key: key, origin: "http://127.0.0.1:18443", wantError: "HTTPS public origin"},
		{name: "origin fragment", cert: cert, key: key, origin: "https://127.0.0.1:18443/#devices", wantError: "exact HTTPS origin"},
		{name: "redirect without TLS", origin: "https://127.0.0.1:18443", redirect: "127.0.0.1:18080", wantError: "requires native TLS"},
		{name: "nonloopback redirect", cert: cert, key: key, origin: "https://127.0.0.1:18443", redirect: "0.0.0.0:18080", wantError: "separate loopback"},
		{name: "same redirect listener", cert: cert, key: key, origin: "https://127.0.0.1:18443", redirect: "127.0.0.1:18443", wantError: "separate loopback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range map[string]string{
				"REMOTE_ENABLED": "true", "REMOTE_LOOPBACK_TEST": "true", "REMOTE_LISTEN": "127.0.0.1:18443",
				"REMOTE_PUBLIC_ORIGIN": tc.origin, "REMOTE_TLS_CERT": tc.cert, "REMOTE_TLS_KEY": tc.key,
				"REMOTE_HTTP_REDIRECT_LISTEN": tc.redirect, "DATABASE_URL": "postgres://test:unused@127.0.0.1/test",
				"REMOTE_SECRET_KEYS": `{"key-1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, "REMOTE_ACTIVE_KEY_VERSION": "key-1",
				"REMOTE_ALLOWED_CIDRS": "", "REMOTE_GATEWAY_PEERS": "{}", "REMOTE_REVOKE_POLL_SECONDS": "5",
			} {
				t.Setenv(name, value)
			}
			cfg, err := LoadConfig()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("expected %q; got %v", tc.wantError, err)
				}
				return
			}
			if err != nil || cfg.TLSCert != tc.cert || cfg.TLSKey != tc.key || cfg.HTTPRedirectListen != tc.redirect {
				t.Fatalf("TLS config was not preserved: %v", err)
			}
		})
	}
}
