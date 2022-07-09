package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"sigs.k8s.io/yaml"

	cosign_sign "github.com/sigstore/cosign/cmd/cosign/cli/sign"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
)

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
		log.Errorf("reading rendered charts %s failed\n", inside)
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
		return err
	} else {
		err = copyFile(flags.owaspDependencyCheckOutput, dirname+"/dependency-check-report.json")
		if err != nil {
			return err
		}
	}

	//Check Kubesec Output
	if _, err := os.Stat(flags.kubesecOutput); errors.Is(err, os.ErrNotExist) {
		log.Errorf("gatherArtifacts - kubesec output not found")
		return err
	} else {
		err = copyFile(flags.kubesecOutput, dirname+"/kubesec-output.json")
		if err != nil {
			return err
		}
	}

	files, err = ioutil.ReadDir(dirname)
	if err != nil {
		log.Errorf("reading rendered charts %s failed\n", inside)
		return err
	}

	blobSignature := filepath.Join(dirname, "blob-signature")
	err = os.Mkdir(blobSignature, 0755)
	if err != nil {
		log.Errorf("error creating directory blob-signature : %w\n", err)
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		err = sign_blob(file.Name(), dirname)
		if err != nil {
			log.Errorf("gatherArtifacts - signing manifest %s failed\n", file.Name())
			return err
		}
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

func sign_blob(blob string, dirname string) error {
	ro := &options.RootOptions{}
	split := strings.Split(blob, ".")
	signatureName := split[0] + ".signature"

	securityKeyOptions := options.SecurityKeyOptions{
		Use:  false,
		Slot: "",
	}
	fulcioOptions := options.FulcioOptions{
		URL:                      "https://fulcio.sigstore.dev",
		IdentityToken:            "",
		InsecureSkipFulcioVerify: false,
	}
	rekor := options.RekorOptions{
		URL: "https://rekor.sigstore.dev",
	}
	oidc := options.OIDCOptions{
		Issuer:      "https://oauth2.sigstore.dev/auth",
		ClientID:    "sigstore",
		RedirectURL: "",
	}
	registry := options.RegistryOptions{
		AllowInsecure:      false,
		KubernetesKeychain: false,
	}

	o := &options.SignBlobOptions{
		Key:               "cosign.key",
		Base64Output:      true,
		Output:            "",
		OutputSignature:   filepath.Join(dirname, "blob-signature", signatureName),
		OutputCertificate: "",
		SecurityKey:       securityKeyOptions,
		Fulcio:            fulcioOptions,
		Rekor:             rekor,
		OIDC:              oidc,
		Registry:          registry,
		BundlePath:        "",
	}

	oidcClientSecret, err := o.OIDC.ClientSecret()
	if err != nil {
		log.Println(err)
		return err
	}

	ko := cosign_sign.KeyOpts{
		KeyRef:                   o.Key,
		PassFunc:                 generate.GetPass,
		Sk:                       o.SecurityKey.Use,
		Slot:                     o.SecurityKey.Slot,
		FulcioURL:                o.Fulcio.URL,
		IDToken:                  o.Fulcio.IdentityToken,
		InsecureSkipFulcioVerify: o.Fulcio.InsecureSkipFulcioVerify,
		RekorURL:                 o.Rekor.URL,
		OIDCIssuer:               o.OIDC.Issuer,
		OIDCClientID:             o.OIDC.ClientID,
		OIDCClientSecret:         oidcClientSecret,
		OIDCRedirectURL:          o.OIDC.RedirectURL,
		BundlePath:               o.BundlePath,
	}

	if _, err := cosign_sign.SignBlobCmd(ro, ko, o.Registry, blob, o.Base64Output, o.OutputSignature, o.OutputCertificate); err != nil {
		log.Errorf("signing %s: %w", blob, err)
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
