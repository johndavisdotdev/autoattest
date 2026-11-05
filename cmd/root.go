// Package cmd is the Cobra routing layer for autoattest.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/locktera/autoattest/attest"
)

// Set at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// ErrNotSafe is returned when attestation completed but at least one check failed.
var ErrNotSafe = errors.New("attestation failed: environment is NOT safe")

// Execute builds and runs the root command.
func Execute() error {
	return NewRootCmd().Execute()
}

// runFunc performs an attestation run; injectable for tests.
type runFunc func(context.Context, attest.Config) (*attest.Report, error)

// NewRootCmd builds the command tree with its own Viper instance.
func NewRootCmd() *cobra.Command {
	return newRootCmd(attest.Run)
}

func newRootCmd(run runFunc) *cobra.Command {
	v := viper.New()

	root := &cobra.Command{
		Use:   "autoattest",
		Short: "Verify this VM and its NVIDIA GPUs are under Confidential Compute protection",
		Long: `autoattest runs a full confidential compute attestation of an Intel TDX
confidential VM and its attached NVIDIA GPUs, and gives a single SAFE / NOT SAFE
verdict.

One fresh nonce binds every piece of evidence:

  Intel TDX   A TD quote with report_data = SHA-512(nonce) is generated via
              configfs-tsm and verified against the pinned Intel SGX Root CA
              using collateral and CRLs from Intel PCS (TCB must be UpToDate).
              The TD must not be in debug mode.

  NVIDIA GPU  CC mode must be ON, DevTools OFF, environment PROD. Each GPU's
              attestation report is signed over the nonce; its signature and
              certificate chain are verified locally against the pinned
              NVIDIA Device Identity CA.

  NRAS        The GPU evidence is verified remotely by the NVIDIA Remote
              Attestation Service. The returned EAT token's ES384 signature,
              issuer and nonce are checked, as are measres=success,
              secboot=true, dbgstat=disabled and every verifier claim
              (report cert chain, report signature, driver/VBIOS RIMs).

Must run as root inside the confidential VM (configfs-tsm requires it).
Exit status is 0 only when every check passes.`,
		Version:       fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig(v, cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := runAttestation(cmd.Context(), v, run)
			if werr := writeReport(cmd.OutOrStdout(), v, rep, err); werr != nil {
				return werr
			}
			if err != nil {
				return err
			}
			if !rep.Safe {
				return ErrNotSafe
			}
			return nil
		},
	}

	pf := root.PersistentFlags()
	pf.String("config", "", "config file (default $HOME/.autoattest.yaml or ./.autoattest.yaml)")
	pf.BoolP("verbose", "v", false, "show informational lines and TD measurements")
	pf.BoolP("json", "j", false, "emit the report as JSON on stdout (for machine consumption)")

	f := root.Flags()
	f.String("nras-url", attest.DefaultNRASURL, "NVIDIA Remote Attestation Service GPU endpoint")
	f.String("claims-version", attest.DefaultClaimsVersion, "NRAS EAT claims version")
	f.String("nras-service-key", "", "optional NVIDIA attestation service key (prefer AUTOATTEST_NRAS_SERVICE_KEY)")
	f.Duration("timeout", attest.DefaultTimeout, "overall timeout for the attestation run")
	f.String("tdx-device", attest.DefaultTDXDevice, "TDX guest device")
	f.String("configfs-root", attest.DefaultConfigfsRoot, "configfs-tsm report directory")
	f.StringP("evidence-dir", "e", "", "save raw evidence (quote, GPU reports, NRAS token, report.json) to this directory")

	return root
}

func initConfig(v *viper.Viper, cmd *cobra.Command) error {
	if cfgFile, _ := cmd.Flags().GetString("config"); cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(home)
		}
		v.AddConfigPath(".")
		v.SetConfigType("yaml")
		v.SetConfigName(".autoattest")
	}

	v.SetEnvPrefix("AUTOATTEST")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); !ok {
			return fmt.Errorf("reading config: %w", err)
		}
	}

	// Binding every flag registers every key, so env-only values are visible
	// to Unmarshal.
	return v.BindPFlags(cmd.Flags())
}

func runAttestation(ctx context.Context, v *viper.Viper, run runFunc) (*attest.Report, error) {
	var cfg attest.Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("decoding config: %w", err)
	}
	return run(ctx, cfg)
}

// writeReport renders the report. In JSON mode stdout always carries exactly
// one JSON document — even when the run failed before producing a report — so
// consumers can rely on parsing it and reading "safe".
func writeReport(w io.Writer, v *viper.Viper, rep *attest.Report, runErr error) error {
	if !v.GetBool("json") {
		if rep == nil {
			return nil // the error is printed to stderr by main
		}
		return rep.WriteText(w, v.GetBool("verbose"))
	}
	if rep == nil {
		rep = &attest.Report{Started: time.Now()}
	}
	if runErr != nil {
		rep.Safe = false
		rep.Error = runErr.Error()
	}
	return rep.WriteJSON(w)
}
