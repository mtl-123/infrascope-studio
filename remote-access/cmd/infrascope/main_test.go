package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"infrascope/remote-access/internal/access"
)

func TestHTTPSRedirectFixedOrigin(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		req := httptest.NewRequest(method, "http://untrusted.example/a%20b?next=https://evil.example", nil)
		rec := httptest.NewRecorder()
		redirectToHTTPS("https://127.0.0.1:18443").ServeHTTP(rec, req)
		if rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") != "https://127.0.0.1:18443/a%20b?next=https://evil.example" {
			t.Fatalf("unsafe redirect: %d %s", rec.Code, rec.Header().Get("Location"))
		}
		if rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("HTTP redirect must not set cookies or be cached")
		}
	}
}

func TestHTTPSRedirectRejectsMutations(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		req := httptest.NewRequest(method, "http://localhost/api/remote/login", nil)
		rec := httptest.NewRecorder()
		redirectToHTTPS("https://127.0.0.1:18443").ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Location") != "" || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("unexpected mutation response: %d", rec.Code)
		}
	}
}

func TestNativeTLSServeNeverFallsBackToHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := serve(ctx, access.Config{Listen: "127.0.0.1:0", TLSCert: "/missing/server.crt", TLSKey: "/missing/server.key", Origin: "https://127.0.0.1"}, http.NotFoundHandler())
	if err == nil || ctx.Err() != nil {
		t.Fatalf("invalid TLS must fail immediately instead of serving HTTP: %v", err)
	}
}

func TestServeRejectsRedirectBindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = serve(ctx, access.Config{Listen: "127.0.0.1:0", HTTPRedirectListen: occupied.Addr().String()}, http.NotFoundHandler())
	if err == nil || ctx.Err() != nil {
		t.Fatalf("redirect binding failure must abort startup: %v", err)
	}
}

func TestNativeTLSActualTransport(t *testing.T) {
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
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	trusted := x509.NewCertPool()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	trusted.AddCert(cert)
	listeners := make([]net.Listener, 2)
	for i := range listeners {
		listeners[i], err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listeners[i].Close()
	}
	cfg := access.Config{Listen: listeners[0].Addr().String(), HTTPRedirectListen: listeners[1].Addr().String(), TLSCert: certPath, TLSKey: keyPath}
	cfg.Origin = "https://" + cfg.Listen
	for _, listener := range listeners {
		listener.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil {
				http.Error(w, "TLS missing", http.StatusInternalServerError)
				return
			}
			io.WriteString(w, "native TLS transport")
		}))
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("TLS server shutdown: %v", err)
			}
		case <-time.After(12 * time.Second):
			t.Error("TLS server failed to stop")
		}
	})
	goodTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trusted, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}}
	defer goodTransport.CloseIdleConnections()
	goodClient := &http.Client{Transport: goodTransport, Timeout: time.Second}
	var response *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response, err = goodClient.Get(cfg.Origin + "/")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("trusted TLS 1.2 connection failed: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "native TLS transport" || response.TLS == nil || response.TLS.Version != tls.VersionTLS12 {
		t.Fatal("native TLS handler did not respond over verified TLS 1.2")
	}
	for _, tc := range []struct {
		name   string
		config *tls.Config
	}{
		{name: "untrusted certificate", config: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}},
		{name: "legacy TLS 1.1", config: &tls.Config{RootCAs: trusted, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: tc.config}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			response, err := client.Get(cfg.Origin)
			if err == nil {
				response.Body.Close()
				t.Fatal("insecure TLS connection unexpectedly succeeded")
			}
		})
	}
	plainClient := &http.Client{Timeout: time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	response, err = plainClient.Get("http://" + cfg.HTTPRedirectListen + "/devices?filter=a%20b")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect || response.Header.Get("Location") != cfg.Origin+"/devices?filter=a%20b" {
		t.Fatal("live HTTP listener did not redirect to configured HTTPS origin")
	}
}
