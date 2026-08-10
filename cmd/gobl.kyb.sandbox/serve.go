package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/invopop/gobl"

	"github.com/invopop/gobl.kyb.sandbox/internal/config"
	"github.com/invopop/gobl.kyb.sandbox/internal/interfaces/web"
)

func serveCmd() *cobra.Command {
	cfg := config.FromEnv()
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the KYB verification HTTP server",
		Long: `Run the sandbox KYB verification server.  Loads the identity from
--config-dir, connects to CouchDB, and serves the standard
well-known endpoints plus the /confirm/<token> pages behind the
emailed confirmation links.

Configuration is read from the environment (CONFIG_DIR, COUCHDB_*,
PUBLIC_BASE_URL, AUTHORITY, SMTP_*, EMAIL_FROM, HTTP_PORT/PORT);
the flags below override it.  Without SMTP_HOST the confirmation
emails are logged instead of sent — development only.

NOTE: This v1 binary terminates HTTP only (no built-in TLS).
Deploy behind a reverse proxy that handles TLS termination.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.ConfigDir == "" {
				return gobl.ErrInput.WithReason("identity directory required: set --config-dir or CONFIG_DIR")
			}
			if cfg.CouchDBURL() == "" {
				return gobl.ErrInput.WithReason("CouchDB connection required: set --couchdb / COUCHDB_URL, or COUCHDB_HOST (+ COUCHDB_USERNAME / COUCHDB_PASSWORD)")
			}
			if cfg.SMTPHost != "" && cfg.EmailFrom == "" {
				return gobl.ErrInput.WithReason("sender address required with SMTP: set --email-from or EMAIL_FROM")
			}
			ctx := cmd.Context()

			setup, cleanup, err := buildDomain(ctx, cfg)
			if err != nil {
				return err
			}
			defer cleanup()

			mux := web.NewMux(setup, slog.Default())

			addr := fmt.Sprintf(":%d", cfg.HTTPPort)
			srv := &http.Server{
				Addr:              addr,
				Handler:           mux,
				ReadHeaderTimeout: 10 * time.Second,
			}

			errCh := make(chan error, 1)
			go func() {
				slog.Info("GOBL Sandbox KYB listening",
					"addr", addr,
					"domain", string(setup.Identity().Address()),
					"authority", string(setup.Verifications().Authority()),
					"public_base_url", setup.PublicBaseURL(),
					"couchdb", cfg.CouchDBRedacted(),
				)
				errCh <- srv.ListenAndServe()
			}()

			select {
			case err := <-errCh:
				if err != nil && err != http.ErrServerClosed {
					return gobl.ErrInternal.WithCause(err)
				}
				return nil
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
				defer cancel()
				slog.Info("shutting down")
				if err := srv.Shutdown(shutdownCtx); err != nil {
					return gobl.ErrInternal.WithCause(err)
				}
				return nil
			}
		},
	}
	cmd.Flags().StringVar(&cfg.ConfigDir, "config-dir", cfg.ConfigDir, "directory holding the verifier identity (env CONFIG_DIR)")
	cmd.Flags().StringVar(&cfg.CouchURL, "couchdb", cfg.CouchURL, "full CouchDB URL, e.g. http://admin:pass@localhost:5984 (env COUCHDB_URL; overrides the COUCHDB_* parts)")
	cmd.Flags().StringVar(&cfg.CouchDatabase, "couchdb-database", cfg.CouchDatabase, "CouchDB database name (env COUCHDB_DATABASE)")
	cmd.Flags().IntVar(&cfg.HTTPPort, "http-port", cfg.HTTPPort, "HTTP listen port (env HTTP_PORT or PORT)")
	cmd.Flags().StringVar(&cfg.PublicBaseURL, "public-base-url", cfg.PublicBaseURL, "canonical https URL used to build /confirm links, defaults to https://<domain> (env PUBLIC_BASE_URL)")
	cmd.Flags().StringVar(&cfg.Authority, "authority", cfg.Authority, "registration authority this verifier works for (env AUTHORITY)")
	cmd.Flags().StringVar(&cfg.SMTPHost, "smtp-host", cfg.SMTPHost, "SMTP submission host; empty logs emails instead of sending (env SMTP_HOST)")
	cmd.Flags().IntVar(&cfg.SMTPPort, "smtp-port", cfg.SMTPPort, "SMTP submission port (env SMTP_PORT)")
	cmd.Flags().StringVar(&cfg.SMTPUsername, "smtp-username", cfg.SMTPUsername, "SMTP username; empty skips authentication (env SMTP_USERNAME)")
	cmd.Flags().StringVar(&cfg.EmailFrom, "email-from", cfg.EmailFrom, `From header of verification emails, e.g. "GOBL Sandbox KYB <kyb@sandbox.gobl.org>" (env EMAIL_FROM)`)
	return cmd
}
