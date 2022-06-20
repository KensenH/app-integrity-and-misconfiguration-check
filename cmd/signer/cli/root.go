package cli

import (
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/kubectl/pkg/scheme"
)

const logLevelEnvKey = "K8S_MANIFEST_SIGSTORE_LOG_LEVEL"

var logLevelMap = map[string]log.Level{
	"panic": log.PanicLevel,
	"fatal": log.FatalLevel,
	"error": log.ErrorLevel,
	"warn":  log.WarnLevel,
	"info":  log.InfoLevel,
	"debug": log.DebugLevel,
	"trace": log.TraceLevel,
}

var KOptions KubectlOptions

var RootCmd = &cobra.Command{
	Use:   "kubectl-sigstore",
	Short: "A command to sign/verify Kubernetes YAML manifests and resources on cluster",
	RunE: func(cmd *cobra.Command, args []string) error {
		return errors.New("kubectl sigstore cannot be invoked without a subcommand operation")
	},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("operation must be specified (e.g. kubectl sigstore sign)")
		}
		return nil
	},
}

func init() {
	KOptions = KubectlOptions{
		// generic options
		ConfigFlags: genericclioptions.NewConfigFlags(true),
		PrintFlags:  genericclioptions.NewPrintFlags("created").WithTypeSetter(scheme.Scheme),
	}

	RootCmd.AddCommand(NewCmdSign())
	RootCmd.AddCommand(NewCmdVerify())
	// RootCmd.AddCommand(NewCmdVerifyResource())
	// RootCmd.AddCommand(NewCmdApplyAfterVerify())
	// RootCmd.AddCommand(NewCmdManifestBuild())
	// RootCmd.AddCommand(NewCmdVersion())

	logLevelStr := os.Getenv(logLevelEnvKey)
	if logLevelStr == "" {
		logLevelStr = "info"
	}
	logLevel, ok := logLevelMap[logLevelStr]
	if !ok {
		logLevel = log.InfoLevel
	}

	log.SetLevel(logLevel)
}
