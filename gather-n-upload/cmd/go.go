package cmd

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	log "github.com/sirupsen/logrus"
)

const letterBytes = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const filenameIfInputIsDir = "manifest.yaml"

type FlagsInput struct {
	chartsPath                 string
	owaspDependencyCheckScan   string
	owaspDependencyCheckOutput string
	kubesecScan                bool
	kubesecOutput              string
	artifactsBucketName        string
	publicKeysBucketName       string
	privateKey                 string
	publicKey                  string
	rm                         bool
	output                     string
}

// goCmd represents the go command
var goCmd = &cobra.Command{
	Use:   "go",
	Short: "gather and upload artifacts in one go",
	Long: `EXAMPLE gathernupload go [FLAGS]

	FLAGS
	-d, --charts-directory path/to/charts/directory
	--owasp-dependency-check-scan path/to/project
	--owasp-dependency-check-output path/to/dependency/check/output.json
	--kubesec-scan , true=scan-manifest, false=skip-scanning
	--kubesec-output path/to/kubesec/output.json
	--artifacts-bucket-name "backend_storage_artifacts_bucket_name"
	--public-keys-bucket-name "backend_storage_public_keys_bucket_name"
	--private-key path/to/key
	--public-key path/to/key

	--rm , delete generated key pair in the end of script

	-c, --config path/to/config

	NOTES
	- if config flag is defined then all flags except chart-directory will be ignored.
	- if private-key is defined but the public-key not or the other way around, the script will generate new key pair instead.
	- backend storage key need to be set on environment variable GOOGLE_APPLICATION_CREDENTIALS="path/to/credentials.json".
	- set COSIGN_PASSWORD environment variable to skip passphrase input
	
	DEPENDENCIES
	- HELM

	`,
	Run: func(cmd *cobra.Command, args []string) {
		//no argument needed
		if len(args) > 0 {
			cmd.Help()
			os.Exit(1)
		}

		//check if backend storage's credential is set
		if !envExist("GOOGLE_APPLICATION_CREDENTIALS") {
			log.Errorf("backend storage credentials is not set, use 'export GOOGLE_APPLICATION_CREDENTIALS=path/to/key' to setup credential")
			os.Exit(1)
		}

		chartsPath, _ := cmd.Flags().GetString("charts-directory")
		owaspDependencyCheckScan, _ := cmd.Flags().GetString("owasp-dependency-check-scan")
		owaspDependencyCheckOutput, _ := cmd.Flags().GetString("owasp-dependency-check-output")
		kubesecScan, _ := cmd.Flags().GetBool("kubesec-scan")
		kubesecOutput, _ := cmd.Flags().GetString("kubesec-output")
		artifactsBucketName, _ := cmd.Flags().GetString("artifacts-bucket-name")
		publicKeysBucketName, _ := cmd.Flags().GetString("public-keys-bucket-name")
		privateKey, _ := cmd.Flags().GetString("private-key")
		publicKey, _ := cmd.Flags().GetString("public-key")
		rm, _ := cmd.Flags().GetBool("rm")
		output, _ := cmd.Flags().GetString("output")

		var flags FlagsInput
		config, _ := cmd.Flags().GetString("config")
		if config != "" {
			log.Infof("config\n")
			var cfg Config
			configByte, err := os.ReadFile(config)
			if err != nil {
				log.Errorf("reading config failed : %t", err)
				os.Exit(1)
			}
			err = yaml.Unmarshal(configByte, &cfg)
			if err != nil {
				log.Errorf("reading config failed : %t", err)
				os.Exit(1)
			}
			flags = FlagsInput{chartsPath, cfg.Scanner.OwaspDependencyCheckScan, cfg.Scanner.OwaspDependencyCheckOutput, cfg.Scanner.KubesecScan, cfg.Scanner.KubesecOutput, cfg.BackendStorage.ArtifactsBucketName, cfg.BackendStorage.PublicKeysBucketName, cfg.Key.PrivateKey, cfg.Key.PublicKey, cfg.Script.Rm, cfg.Output}
		} else {
			log.Infof("not config\n")
			//move all flags inputted to struct
			flags = FlagsInput{chartsPath, owaspDependencyCheckScan, owaspDependencyCheckOutput, kubesecScan, kubesecOutput, artifactsBucketName, publicKeysBucketName, privateKey, publicKey, rm, output}
		}

		//check if charts directory inputted is exist
		if _, err := os.Stat(flags.chartsPath); os.IsNotExist(err) {
			log.Errorf("%s dir not found", flags.chartsPath)
			os.Exit(1)
		}

		// input := Input(cmd.Flags().GetString("charts-directory"))
		id := randStringBytes(15)
		dirname := id + "_artifacts"

		if flags.privateKey == "" || flags.publicKey == "" {
			err := makeKeyPair(cmd.Context())
			if err != nil {
				log.Errorf("creating key: %w", err)
				os.Exit(1)
			}
		} else {
			err := copyFile(flags.privateKey, "./cosign.key")
			if err != nil {
				log.Errorf("moving private key failed: %w", err)
				os.Exit(1)
			}

			err = copyFile(flags.publicKey, "./cosign.pub")
			if err != nil {
				log.Errorf("moving public key failed: %w", err)
				os.Exit(1)
			}
		}

		err := gatherArtifacts(id, flags, dirname)
		if err != nil {
			log.Errorf("gathering artifacts: %w", err)
			os.Exit(1)
		}

		err = uploadArtifacts(dirname, flags.artifactsBucketName)
		if err != nil {
			log.Errorf("upload artifacts: %w", err)
			os.Exit(1)
		}

		err = uploadPublicKey(id, flags.publicKeysBucketName)
		if err != nil {
			log.Errorf("upload public key: %w", err)
			os.Exit(1)
		}

		if output != "" {
			folderPath := fmt.Sprintf("%s_artifacts/Charts/templates/*", id)
			destination := filepath.Join(flags.output, id)
			copyFolder(folderPath, destination)
		}

		if flags.rm {
			os.Remove("cosign.key")
			os.Remove("cosign.pub")
		}
	},
}

func copyFolder(folderPath string, destination string) {
	cmd := exec.Command("mkdir", destination)

	
	cmd := exec.Command("cp", "--recursive", folderPath, destination)
	cmd.Run()	
}	

func randStringBytes(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func makeKeyPair(ctx context.Context) error {
	var empty_list []string

	err := generate.GenerateKeyPairCmd(ctx, "", empty_list)
	if err != nil {
		return err
	}

	return nil
}

func envExist(name string) bool {
	_, exist := os.LookupEnv(name)
	return exist
}

func init() {
	rootCmd.AddCommand(goCmd)

	goCmd.Flags().StringP("charts-directory", "d", "", "path to charts folder/directory")
	goCmd.Flags().StringP("owasp-dependency-check-scan", "", "", "project's path to scan (leave empty to skip scanning)")
	goCmd.Flags().StringP("owasp-dependency-check-output", "", "./dependency-check-report.json", "path to owasp dependency check output")
	goCmd.Flags().BoolP("kubesec-scan", "", false, "if true, script will scan manifests, else will skip scanning")
	goCmd.Flags().StringP("kubesec-output", "", "./kubesec-output.json", "path to kubesec output")
	goCmd.Flags().BoolP("rm", "", false, "delete key after process (both key pair need to be in the same directory)")
	goCmd.Flags().StringP("artifacts-bucket-name", "", "", "bucket name to upload artifacts")
	goCmd.Flags().StringP("public-keys-bucket-name", "", "", "bucket name to upload public key")
	goCmd.Flags().StringP("private-key", "", "", "private key path")
	goCmd.Flags().StringP("public-key", "", "", "private key path")
	goCmd.Flags().StringP("config", "c", "", "path to config")
	goCmd.Flags().StringP("output", "o", "", "output")

	// goCmd.MarkFlagRequired("public-keys-bucket-name")
	// goCmd.MarkFlagRequired("artifacts-bucket-name")
	goCmd.MarkFlagRequired("charts-directory")
}
