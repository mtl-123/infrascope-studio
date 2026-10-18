package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"infrascope/remote-access/internal/access"
	"infrascope/remote-access/migrations"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "InfraScope startup failed:", e)
		os.Exit(1)
	}
}
func run() error {
	cfg, e := access.LoadConfig()
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if !cfg.Enabled && (len(os.Args) == 1 || os.Args[1] == "serve") {
		fmt.Println("Remote module disabled; serving the existing site only")
		return serve(ctx, cfg, (&access.App{Config: cfg}).Handler())
	}
	app, e := access.New(ctx, cfg)
	if e != nil {
		return fmt.Errorf("database unavailable (check DATABASE_URL and TLS configuration)")
	}
	defer app.Close()
	mode := "serve"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "migrate":
		tx, e := app.DB.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, migrations.SQL); e != nil {
			return e
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
		fmt.Println("InfraScope migrations 001-008 applied transactionally")
		return nil
	case "rotate-keys":
		return app.RotateKeys(ctx)
	case "bootstrap":
		var in struct {
			Username    string `json:"username"`
			DisplayName string `json:"displayName"`
			Password    string `json:"password"`
		}
		d := json.NewDecoder(os.Stdin)
		d.DisallowUnknownFields()
		if e = d.Decode(&in); e != nil {
			return fmt.Errorf("read bootstrap JSON from stdin; no password arguments")
		}
		e = app.Bootstrap(ctx, in.Username, in.DisplayName, in.Password)
		in.Password = ""
		if e == nil {
			fmt.Println("Administrator created; bootstrap is now locked")
		}
		return e
	case "serve":
		if e = app.StartBackground(ctx); e != nil {
			return e
		}
		return serve(ctx, cfg, app.Handler())
	default:
		return fmt.Errorf("command must be serve, migrate, bootstrap, or rotate-keys")
	}
}

func redirectToHTTPS(origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Use the HTTPS origin for API requests", http.StatusMethodNotAllowed)
			return
		}
		path := r.URL.EscapedPath()
		if path == "" {
			path = "/"
		}
		// Never derive the destination origin from the request Host header.
		target := origin + path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})
}

func serve(ctx context.Context, cfg access.Config, handler http.Handler) error {
	server := &http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 70 * time.Second, MaxHeaderBytes: 32768, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	servers := []*http.Server{server}
	var redirectListener net.Listener
	if cfg.HTTPRedirectListen != "" {
		redirectListener, err = net.Listen("tcp", cfg.HTTPRedirectListen)
		if err != nil {
			return fmt.Errorf("HTTP redirect listener: %w", err)
		}
		defer redirectListener.Close()
		servers = append(servers, &http.Server{Addr: cfg.HTTPRedirectListen, Handler: redirectToHTTPS(cfg.Origin), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32768})
	}
	errors := make(chan error, len(servers))
	go func() {
		if cfg.TLSCert != "" {
			errors <- server.ServeTLS(listener, cfg.TLSCert, cfg.TLSKey)
		} else {
			errors <- server.Serve(listener)
		}
	}()
	if redirectListener != nil {
		go func() { errors <- servers[1].Serve(redirectListener) }()
	}
	if cfg.TLSCert != "" {
		fmt.Println("InfraScope Local HTTPS:", cfg.Origin, "remote access enabled:", cfg.Enabled)
	} else {
		fmt.Println("InfraScope listening on", cfg.Listen, "remote access enabled:", cfg.Enabled)
	}
	select {
	case <-ctx.Done():
	case err = <-errors:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, current := range servers {
		if shutdownErr := current.Shutdown(shutdown); shutdownErr != nil {
			current.Close()
			if err == nil {
				err = shutdownErr
			}
		}
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
