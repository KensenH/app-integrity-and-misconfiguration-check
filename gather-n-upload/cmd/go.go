/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const letterBytes = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const filenameIfInputIsDir = "manifest.yaml"

// goCmd represents the go command
var goCmd = &cobra.Command{
	Use:   "go",
	Short: "gather and upload artifacts in one go",
	Long: `EXAMPLE gathernupload go [FLAGS]
	Flags
	-b, --backend-storage-key path/to/key

	
	`,
	Run: func(cmd *cobra.Command, args []string) {
		id := randStringBytes(15)

		err := makeKeyPair(cmd.Context())
		if err != nil {
			fmt.Errorf("creating key: %w", err)
		}

		err = gatherArtifacts(id)
		if err != nil {
			fmt.Errorf("gathering artifacts: %w", err)
		}

	},
}

func gatherArtifacts(id string) error {
	//create folder
	dirname := id + "_artifacts"
	err := os.Mkdir(dirname, 0755)
	if err != nil {
		return err
	}

	chartsPath := "./sample_charts"

	//render manifest from charts
	prep_command := "helm template " + chartsPath + " --output-dir " + dirname
	render_cmd := exec.Command("bash", "-c", prep_command)

	err = render_cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	inside := dirname + "/Charts/templates/"
	files, err := ioutil.ReadDir(inside)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		var mty []string
		temp_full_path := inside + file.Name()
		err = sign(temp_full_path, "", "cosign.key", temp_full_path, false, true, mty)
		if err != nil {
			log.Fatalf("error occurred during signing: %s", err.Error())
			return nil
		}

	}

	return nil
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// goCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// goCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
