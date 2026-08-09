package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/invopop/gobl"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb.sandbox/internal/config"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain"
)

func redeliverCmd() *cobra.Command {
	cfg := config.FromEnv()
	cmd := &cobra.Command{
		Use:   "redeliver <address>",
		Short: "Re-deliver a confirmed verification to the registration authority",
		Long: `Load the confirmed verification for <address>, countersign a fresh
copy of the stored envelope (iss=<verifier>, aud=<address>, a
year-long exp), and POST it to the registration authority's /inbox.

Delivery normally happens automatically when the subject confirms
the emailed attestation; this command exists for recovery when
that delivery failed (status "failed").`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.ConfigDir == "" {
				return gobl.ErrInput.WithReason("identity directory required: set --config-dir or CONFIG_DIR")
			}
			if cfg.CouchDBURL() == "" {
				return gobl.ErrInput.WithReason("CouchDB connection required: set --couchdb / COUCHDB_URL, or COUCHDB_HOST (+ COUCHDB_USERNAME / COUCHDB_PASSWORD)")
			}
			addr, err := goblnet.ParseAddress(args[0])
			if err != nil {
				return gobl.ErrInput.WithCause(err)
			}
			ctx := cmd.Context()

			setup, cleanup, err := buildDomain(ctx, cfg)
			if err != nil {
				return err
			}
			defer cleanup()

			rec, err := setup.Verifications().Redeliver(ctx, addr)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrValidation) {
					return gobl.ErrInput.WithCause(err)
				}
				return gobl.ErrInternal.WithCause(err)
			}
			slog.Info("verification delivered",
				"address", string(addr),
				"envelope", rec.EnvelopeUUID.String(),
				"authority", string(setup.Verifications().Authority()),
			)
			_, _ = fmt.Fprintf(stdOut(cmd), "delivered verification of %s to %s (envelope %s)\n", addr, setup.Verifications().Authority(), rec.EnvelopeUUID)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfg.ConfigDir, "config-dir", cfg.ConfigDir, "directory holding the verifier identity (env CONFIG_DIR)")
	cmd.Flags().StringVar(&cfg.CouchURL, "couchdb", cfg.CouchURL, "full CouchDB URL (env COUCHDB_URL; overrides the COUCHDB_* parts)")
	cmd.Flags().StringVar(&cfg.CouchDatabase, "couchdb-database", cfg.CouchDatabase, "CouchDB database name (env COUCHDB_DATABASE)")
	cmd.Flags().StringVar(&cfg.Authority, "authority", cfg.Authority, "registration authority to deliver to (env AUTHORITY)")
	return cmd
}
