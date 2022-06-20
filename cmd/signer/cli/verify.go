package cli

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/ghodss/yaml"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func NewCmdVerify() *cobra.Command {

	var imageRef string
	var filename string
	var keyPath string
	var configPath string
	cmd := &cobra.Command{
		Use:   "verify -f FILENAME [-i IMAGE]",
		Short: "A command to verify Kubernetes YAML manifests",
		RunE: func(cmd *cobra.Command, args []string) error {

			err := verify(filename, imageRef, keyPath, configPath)
			if err != nil {
				return err
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&filename, "filename", "f", "", "file name which will be verified")
	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "a comma-separated list of signed image names that contains YAML manifests")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "a comma-separated list of paths to public keys or environment variable names start with \"env://\" (if empty, do key-less verification)")
	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to verification config YAML file (for advanced verification)")

	return cmd
}

func verify(filename, imageRef, keyPath, configPath string) error {
	manifest, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}

	vo := &k8smanifest.VerifyManifestOption{}
	if configPath != "" {
		vo, err = k8smanifest.LoadVerifyManifestConfig(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return nil
		}
	}
	// add signature/message/others annotations to ignore fields
	vo.SetAnnotationIgnoreFields()

	annotations := k8ssigutil.GetAnnotationsInYAML(manifest)
	imageRefAnnotationKey := vo.AnnotationConfig.ImageRefAnnotationKey()
	annoImageRef, annoImageRefFound := annotations[imageRefAnnotationKey]
	if imageRef == "" && annoImageRefFound {
		imageRef = annoImageRef
	}
	log.Debug("annotations", annotations)
	log.Debug("imageRef", imageRef)

	if imageRef != "" {
		vo.ImageRef = imageRef
	}
	if keyPath != "" {
		vo.KeyPath = keyPath
	}

	objManifests := k8ssigutil.SplitConcatYAMLs(manifest)
	verified := false
	verifiedCount := 0
	signerName := ""
	diffMsg := ""
	var reterr error
	for _, objManifest := range objManifests {
		result, verr := k8smanifest.VerifyManifest(objManifest, vo)
		if verr != nil {
			reterr = verr
			break
		}
		if result != nil {
			if result.Verified {
				signerName = result.Signer
				verifiedCount += 1
			} else if result.Diff != nil && result.Diff.Size() > 0 {
				var obj unstructured.Unstructured
				_ = yaml.Unmarshal(objManifest, &obj)
				kind := obj.GetKind()
				name := obj.GetName()
				diffMsg = fmt.Sprintf("Diff found in %s %s, diffs:%s", kind, name, result.Diff.String())
				break
			}
		}
	}
	if verifiedCount == len(objManifests) {
		verified = true
	}
	if verified {
		if signerName == "" {
			log.Infof("verifed: %s", strconv.FormatBool(verified))
		} else {
			log.Infof("verifed: %s, signerName: %s", strconv.FormatBool(verified), signerName)
		}
	} else {
		errMsg := ""
		if reterr != nil {
			errMsg = reterr.Error()
		} else {
			errMsg = diffMsg
		}
		log.Fatalf("verifed: %s, error: %s", strconv.FormatBool(verified), errMsg)
	}

	return nil
}
