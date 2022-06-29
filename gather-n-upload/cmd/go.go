package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

const letterBytes = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const filenameIfInputIsDir = "manifest.yaml"

type FlagsInput struct {
	chartsPath                 string
	keyPath                    string
	owaspDependencyCheckScan   string
	owaspDependencyCheckOutput string
	kubesecScan                bool
	kubesecOutput              string
	artifactsBucketName        string
	publicKeysBucketName       string
}

// goCmd represents the go command
var goCmd = &cobra.Command{
	Use:   "go",
	Short: "gather and upload artifacts in one go",
	Long: `EXAMPLE gathernupload go [FLAGS]

	FLAGS
	-c, --charts-directory path/to/charts/directory
	--owasp-dependency-check-scan path/to/project
	--owasp-dependency-check-output path/to/dependency/check/output.json
	--kubesec-scan true/false , true=scan-manifest, false=skip-scanning
	--kubesec-output path/to/kubesec/output.json
	--artifacts-bucket-name "backend_storage_artifacts_bucket_name"
	--public-keys-bucket-name "backend_storage_public_keys_bucket_name"

	NOTES
	- gathernupload go command don't need any args but flags
	- backend storage key need to be set on environment variable GOOGLE_APPLICATION_CREDENTIALS="path/to/credentials.json"
	
	DEPENDENCIES
	- HELM

	`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) > 0 {
			cmd.Help()
			os.Exit(1)
		}

		//check if backend storage's credential is set
		if !envExist("GOOGLE_APPLICATION_CREDENTIALS") {
			log.Errorf("backend storage credentials is not set, use 'export GOOGLE_APPLICATION_CREDENTIALS=path/to/key' to setup credential")
		}

		//move all flags inputted to struct
		chartsPath, _ := cmd.Flags().GetString("charts-directory")
		backendStorageKey, _ := cmd.Flags().GetString("backend-storage-key")
		owaspDependencyCheckScan, _ := cmd.Flags().GetString("owasp-dependency-check-scan")
		owaspDependencyCheckOutput, _ := cmd.Flags().GetString("owasp-dependency-check-output")
		kubesecScan, _ := cmd.Flags().GetBool("kubesec-scan")
		kubesecOutput, _ := cmd.Flags().GetString("kubesec-output")
		artifactsBucketName, _ := cmd.Flags().GetString("artifacts-bucket-name")
		publicKeysBucketName, _ := cmd.Flags().GetString("public-keys-bucket-name")

		flags := FlagsInput{chartsPath, backendStorageKey, owaspDependencyCheckScan, owaspDependencyCheckOutput, kubesecScan, kubesecOutput, artifactsBucketName, publicKeysBucketName}

		//check if charts directory inputted is exist
		if _, err := os.Stat(flags.chartsPath); os.IsNotExist(err) {
			log.Errorf("%s dir not found", flags.chartsPath)
			os.Exit(1)
		}

		// input := Input(cmd.Flags().GetString("charts-directory"))
		id := randStringBytes(15)
		dirname := id + "_artifacts"

		err := makeKeyPair(cmd.Context())
		if err != nil {
			log.Errorf("creating key: %w", err)
			os.Exit(1)
		}

		err = gatherArtifacts(id, flags, dirname)
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
	},
}

func uploadPublicKey(id string, bucketname string) error {
	err := uploadFileToBackendStorage("./cosign.pub", bucketname, id+".pub")
	if err != nil {
		log.Errorf("upload public key error")
		return err
	}
	return nil
}

func uploadArtifacts(dirname string, bucketname string) error {
	err := filepath.Walk(dirname, func(path string, info fs.FileInfo, err error) error {
		file, err := os.Open(path)
		if err != nil {
			log.Errorf("uploadArtifacts - error when opening file %s", path)
			return err
		}

		defer file.Close()

		fileInfo, err := file.Stat()
		if err != nil {
			log.Errorf("uploadArtifacts - error when getting file %s info", fileInfo)
			return err
		}

		if !fileInfo.IsDir() {
			err = uploadFileToBackendStorage(path, bucketname, path)
			if err != nil {
				log.Errorf("uploadArtifacts - upload file to backend storage failed")
				return err
			}
		}

		return nil
	})
	if err != nil {
		log.Errorf("uploadArtifacts - error when walking through %s", dirname)
		return err
	}
	return nil
}

func uploadFileToBackendStorage(filePath string, bucketname string, object string) error {
	ctx := context.Background()

	// Creates a client.
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
		return err
	}
	defer client.Close()

	f, err := os.Open(filePath)
	if err != nil {
		log.Errorf("os.Open: %v", err)
		return err
	}
	defer f.Close()

	ctx, cancel := context.WithTimeout(ctx, time.Second*50)
	defer cancel()

	o := client.Bucket(bucketname).Object(object)
	o = o.If(storage.Conditions{DoesNotExist: true})

	wc := o.NewWriter(ctx)
	if _, err = io.Copy(wc, f); err != nil {
		log.Errorf("io.Copy: %v", err)
		return err
	}
	if err := wc.Close(); err != nil {
		log.Errorf("Writer.Close: %v", err)
		return err
	}
	fmt.Fprintf(os.Stdout, "Blob %v uploaded.\n", object)

	return nil
}

func gatherArtifacts(id string, flags FlagsInput, dirname string) error {

	//create folder
	err := os.Mkdir(dirname, 0755)
	if err != nil {
		log.Errorf("making dir %s failed\n", dirname)
		return err
	}

	//render manifest from charts
	prep_command := "helm template " + flags.chartsPath + " --output-dir " + dirname
	render_cmd := exec.Command("bash", "-c", prep_command)

	err = render_cmd.Run()
	if err != nil {
		log.Errorf("rendering charts failed\n")
		return err
	}

	inside := filepath.Join(dirname, "/Charts/templates")
	files, err := ioutil.ReadDir(inside)
	if err != nil {
		log.Errorf("reading rendered charts failed\n")
		return err
	}

	var imageRef string = ""
	var keyPath string = "cosign.key"
	var applySignatureConfigMap bool = false
	var updateAnnotation bool = true
	var imageAnnotations []string

	//sign kubernetes manifest
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		temp_full_path := filepath.Join(inside, file.Name())

		err = giveManifestId(temp_full_path, file.Name(), id)
		if err != nil {
			log.Errorf("gatherArtifacts - attaching id to manifest %s failed\n", file.Name())
			return err
		}

		err = sign(temp_full_path, imageRef, keyPath, temp_full_path, applySignatureConfigMap, updateAnnotation, imageAnnotations)
		if err != nil {
			log.Errorf("gatherArtifacts - signing manifest %s failed\n", file.Name())
			return err
		}
	}

	//Check OWASP Dependency Check Output
	if _, err := os.Stat(flags.owaspDependencyCheckOutput); errors.Is(err, os.ErrNotExist) {
		log.Errorf("gatherArtifacts - OWASP Dependency Check output not found")
		os.Exit(1)
	} else {
		err = copyFile(flags.owaspDependencyCheckOutput, dirname+"/dependency-check-report.json")
		if err != nil {
			return err
		}
	}

	//Check Kubesec Output
	if _, err := os.Stat(flags.kubesecOutput); errors.Is(err, os.ErrNotExist) {
		log.Errorf("gatherArtifacts - kubesec output not found")
		os.Exit(1)
	} else {
		err = copyFile(flags.kubesecOutput, dirname+"/kubesec-output.json")
		if err != nil {
			return err
		}
	}

	return nil
}

func copyFile(src string, dst string) error {
	fin, err := os.Open(src)
	if err != nil {
		return err
	}
	defer fin.Close()

	fout, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer fout.Close()

	_, err = io.Copy(fout, fin)

	if err != nil {
		return err
	}

	return nil
}

func giveManifestId(temp_full_path string, filename string, id string) error {
	files, err := ioutil.ReadFile(temp_full_path)
	if err != nil {
		log.Errorf("giveManifestId - error reading files %s", temp_full_path)
		return err
	}

	var manifest map[string]interface{}
	if err := yaml.Unmarshal(files, &manifest); err != nil {
		log.Errorf("giveManifestId - unmarshal yaml failed")
		return err
	}
	metadata := manifest["metadata"].(map[string]interface{})
	annotationsExist := keyExistInterface(manifest["metadata"].(map[string]interface{}), "annotations")

	if !annotationsExist {
		metadata["annotations"] = map[string]interface{}{}
		manifest["metadata"] = metadata
	}

	annotations := manifest["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})
	annotations["gnup-id"] = id + "_" + filename
	manifest["metadata"].(map[string]interface{})["annotations"] = annotations

	newYaml, err := yaml.Marshal(manifest)
	if err != nil {
		log.Errorf("giveManifestId - marshaling to newYaml failed")
		return err
	}

	err = ioutil.WriteFile(temp_full_path, newYaml, 0)
	if err != nil {
		log.Errorf("giceManifestId - writefile to %s failed", temp_full_path)
		return err
	}

	return nil
}

func keyExistInterface(data map[string]interface{}, key string) bool {
	if _, ok := data[key]; ok {
		return true
	}
	return false
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

	_, passphrase := os.LookupEnv("COSIGN_PASSWORD")
	if !passphrase {
		os.Setenv("COSIGN_PASSWORD", "")
	}

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

func sign(inputDir, imageRef, keyPath, output string, applySignatureConfigMap, updateAnnotation bool, annotations []string) error {
	if output == "" && updateAnnotation {
		if isDir, _ := k8smnfutil.IsDir(inputDir); isDir {
			// e.g.) "./yamls/" --> "./yamls/manifest.yaml.signed"
			output = filepath.Join(inputDir, filenameIfInputIsDir+".signed")
		} else {
			// e.g.) "configmap.yaml" --> "configmap.yaml.signed"
			output = inputDir + ".signed"
		}
	}

	var anntns map[string]interface{}
	var err error
	if len(annotations) > 0 {
		anntns, err = parseAnnotations(annotations)
		if err != nil {
			return err
		}
	}

	so := &k8smanifest.SignOption{
		ImageRef:         imageRef,
		KeyPath:          keyPath,
		Output:           output,
		UpdateAnnotation: updateAnnotation,
		ImageAnnotations: anntns,
	}

	if applySignatureConfigMap && strings.HasPrefix(output, kubeutil.InClusterObjectPrefix) {
		so.ApplySigConfigMap = true
	}

	_, err = k8smanifest.Sign(inputDir, so)
	if err != nil {
		return err
	}
	if so.UpdateAnnotation {
		finalOutput := output
		if strings.HasPrefix(output, kubeutil.InClusterObjectPrefix) && !applySignatureConfigMap {
			finalOutput = k8smanifest.K8sResourceRef2FileName(output)
		}
		log.Info("signed manifest generated at ", finalOutput)
	}
	return nil
}

func parseAnnotations(annotations []string) (map[string]interface{}, error) {
	annotationsMap := map[string]interface{}{}

	for _, annotation := range annotations {
		kvp := strings.SplitN(annotation, "=", 2)
		if len(kvp) != 2 {
			return nil, fmt.Errorf("invalid flag: %s, expected key=value", annotation)
		}

		annotationsMap[kvp[0]] = kvp[1]
	}
	return annotationsMap, nil
}

func init() {
	rootCmd.AddCommand(goCmd)

	goCmd.Flags().StringP("charts-directory", "c", "", "path to charts folder/directory")
	goCmd.Flags().StringP("owasp-dependency-check-scan", "", "", "project's path to scan (leave empty to skip scanning)")
	goCmd.Flags().StringP("owasp-dependency-check-output", "", "./dependency-check-report.json", "path to owasp dependency check output")
	goCmd.Flags().BoolP("kubesec-scan", "", false, "if true, script will scan manifests, else will skip scanning")
	goCmd.Flags().StringP("kubesec-output", "", "./kubesec-output.json", "path to kubesec output")
	goCmd.Flags().BoolP("rm-key", "", true, "delete key after process (both key pair need to be in the same directory)")
	goCmd.Flags().StringP("artifacts-bucket-name", "", "", "bucket name to upload artifacts")
	goCmd.Flags().StringP("public-keys-bucket-name", "", "", "bucket name to upload public key")

	goCmd.MarkFlagRequired("public-keys-bucket-name")
	goCmd.MarkFlagRequired("artifacts-bucket-name")
	goCmd.MarkFlagRequired("charts-directory")
}
