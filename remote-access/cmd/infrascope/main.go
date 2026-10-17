package main

import (
	"context"
	"encoding/json"
	"fmt"
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
		return http.ListenAndServe(cfg.Listen, (&access.App{Config: cfg}).Handler())
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
		fmt.Println("Remote access migration 001 applied transactionally")
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
		server := &http.Server{Addr: cfg.Listen, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 70 * time.Second, MaxHeaderBytes: 32768}
		go func() {
			<-ctx.Done()
			c, cc := context.WithTimeout(context.Background(), 10*time.Second)
			defer cc()
			server.Shutdown(c)
		}()
		fmt.Println("InfraScope listening on", cfg.Listen, "remote access enabled:", cfg.Enabled)
		e = server.ListenAndServe()
		if e == http.ErrServerClosed {
			return nil
		}
		return e
	default:
		return fmt.Errorf("command must be serve, migrate, bootstrap, or rotate-keys")
	}
}
