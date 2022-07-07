package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/r3labs/diff"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	cosign_verify "github.com/sigstore/cosign/cmd/cosign/cli/verify"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	yaml3 "gopkg.in/yaml.v3"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
)

const letterBytes = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var config *Config
var ctx context.Context

func init() {
	cfg, err := os.ReadFile("config.yaml")
	if err != nil {
		logrus.Errorf("init config failed : %t", err)
	}

	err = yaml3.Unmarshal(cfg, &config)
	if err != nil {
		logrus.Errorf("init config failed : %t", err)
	}
}

func main() {
	setLogger()
	// handle our core application
	http.HandleFunc("/validate", ServeValidate)
	// http.HandleFunc("/mutate-pods", ServeMutatePods)
	http.HandleFunc("/health", ServeHealth)

	// start the server
	// listens to clear text http on port 8080 unless TLS env var is set to "true"
	if os.Getenv("TLS") == "true" {
		cert := "/etc/admission-webhook/tls/tls.crt"
		key := "/etc/admission-webhook/tls/tls.key"
		logrus.Print("Listening on port 443...")
		logrus.Fatal(http.ListenAndServeTLS(":443", cert, key, nil))
	} else {
		logrus.Print("Listening on port 8080...")
		logrus.Fatal(http.ListenAndServe(":8080", nil))
	}
}

// ServeHealth returns 200 when things are good
func ServeHealth(w http.ResponseWriter, r *http.Request) {
	logrus.WithField("uri", r.RequestURI).Debug("healthy")
}

// ServeValidatePods validates an admission request and then writes an admission
// review to `w`
func ServeValidate(w http.ResponseWriter, r *http.Request) {
	logger := logrus.WithField("uri", r.RequestURI)
	logger.Debug("received validation request")

	in, err := parseRequest(*r)
	if err != nil {
		logger.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var obj map[string]interface{}
	err = json.Unmarshal(in.Request.Object.Raw, &obj)
	if err != nil {
		logger.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	out, err := validateManifest(obj, in)
	if err != nil {
		e := fmt.Sprintf("could not generate admission response: %v", err)
		logger.Error(e)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	jout, err := json.Marshal(out)
	if err != nil {
		e := fmt.Sprintf("could not parse admission response: %v", err)
		logger.Error(e)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	logger.Debug("sending response")
	logger.Debugf("%s", jout)
	fmt.Fprintf(w, "%s", jout)
}

// setLogger sets the logger using env vars, it defaults to text logs on
// debug level unless otherwise specified
func setLogger() {
	logrus.SetLevel(logrus.DebugLevel)

	lev := os.Getenv("LOG_LEVEL")
	if lev != "" {
		llev, err := logrus.ParseLevel(lev)
		if err != nil {
			logrus.Fatalf("cannot set LOG_LEVEL to %q", lev)
		}
		logrus.SetLevel(llev)
	}

	if os.Getenv("LOG_JSON") == "true" {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}
}

// parseRequest extracts an AdmissionReview from an http.Request if possible
func parseRequest(r http.Request) (*admissionv1.AdmissionReview, error) {
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("Content-Type: %q should be %q",
			r.Header.Get("Content-Type"), "application/json")
	}

	bodybuf := new(bytes.Buffer)
	bodybuf.ReadFrom(r.Body)
	body := bodybuf.Bytes()

	if len(body) == 0 {
		return nil, fmt.Errorf("admission request body is empty")
	}

	var a admissionv1.AdmissionReview

	if err := json.Unmarshal(body, &a); err != nil {
		return nil, fmt.Errorf("could not parse admission review request: %v", err)
	}

	if a.Request == nil {
		return nil, fmt.Errorf("admission review can't be used: Request field is nil")
	}

	return &a, nil
}

func validateManifest(obj map[string]interface{}, in *admissionv1.AdmissionReview) (*admissionv1.AdmissionReview, error) {
	//Check if this resource spawned by an owner resource
	var err error
	objMetadata := obj["metadata"].(map[string]interface{})

	//check namespace if not default then, approve
	namespace := objMetadata["namespace"].(string)
	if !contains(config.NamespaceRestricted, namespace) {
		return reviewResponse(in.Request.UID, true, http.StatusAccepted, "namespace not restricted"), nil
	}

	//check if resource have parent, if yes then approve
	if _, ok := objMetadata["ownerReferences"]; ok {
		return reviewResponse(in.Request.UID, true, http.StatusAccepted, "child resource"), nil
	}

	//check if there is cosign signature and gnup-id
	objAnnotations := objMetadata["annotations"].(map[string]interface{})
	if _, ok := objAnnotations["cosign.sigstore.dev/message"]; !ok {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "signature/message annotation not found"), nil
	}
	if _, ok := objAnnotations["cosign.sigstore.dev/signature"]; !ok {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "signature/signature annotation not found"), nil
	}
	if _, ok := objAnnotations["gnup-id"]; !ok {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "gnup-id annotation not found"), nil
	}

	gnupId := strings.Split(objAnnotations["gnup-id"].(string), "_")

	//rand string to avoid race conditions
	folderName := randStringBytes(5) + "_" + gnupId[0]

	//create folder with unique name
	if err := os.Mkdir(folderName, os.ModePerm); err != nil {
		log.Fatal(err)
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "gnup-id annotation not found"), err
	}

	//list all object related to gnup-id
	objectList, err := getObjectList(gnupId[0]+"_artifacts/", "", config.BackendStorage.ArtifactsBucketName)
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "listing object failed"), err
	}

	err = downloadListFromStorage(folderName, objectList, config.BackendStorage.ArtifactsBucketName)
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "downloading list from storage failed"), err
	}

	err = downloadPublicKeyFromStorage(folderName, gnupId[0], config.BackendStorage.PublicKeysBucketName)
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "downloading public key from storage failed: "), err
	}

	verified, err := verifyArtifacts(folderName)
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "verifying artifacts process failed"), err
	}
	if !verified {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "failed artifacts integrity test"), err
	}

	verified, err = verifyManifest(folderName, gnupId[1], obj)
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "verifying manifest process failed"), err
	}
	if !verified {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "failed manifest integrity test"), err
	}

	rulesMatch, msg, err := rulesValidation(config.Rules, folderName, gnupId[1])
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "rules matching failed"), err
	}

	if !rulesMatch {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, msg), err
	}

	return reviewResponse(in.Request.UID, true, http.StatusAccepted, ""), err
}

func clean() error {

	return nil
}

func rulesValidation(rules Rules, folderName string, filename string) (bool, string, error) {
	//OWASP Dependency Check
	var dependencyCheckOutput DependencyCheckOutput
	result := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	severityScore := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

	//cvss v3 base score
	attackVector := map[string]int{"NETWORK": 4, "ADJACENT": 3, "LOCAL": 2, "PHYSICAL": 1}
	attackComplexity := map[string]int{"LOW": 2, "HIGH": 1}
	privilegesRequired := map[string]int{"NONE": 3, "LOW": 2, "HIGH": 1}
	userInteraction := map[string]int{"NONE": 2, "REQUIRED": 1}
	scope := map[string]int{"CHANGED": 2, "UNCHANGED": 1}
	confidentialityImpact := map[string]int{"HIGH": 3, "LOW": 2, "NONE": 1}
	integrityImpact := map[string]int{"HIGH": 3, "LOW": 2, "NONE": 1}
	availabilityImpact := map[string]int{"HIGH": 3, "LOW": 2, "NONE": 1}

	dependencyCheckOutputPath := filepath.Join(folderName, "dependency-check-report.json")
	dependencyCheckBytes, err := os.ReadFile(dependencyCheckOutputPath)
	if err != nil {
		logrus.Errorf("error while reading file %s : %w", &dependencyCheckOutputPath, err)
		return false, "error", err
	}
	err = json.Unmarshal(dependencyCheckBytes, &dependencyCheckOutput)

	for _, dependency := range dependencyCheckOutput.Dependencies {
		var cvssv3 Cvssv3
		if dependency.Vulnerabilities == nil {
			continue
		}
		var severity string
		for _, vuln := range dependency.Vulnerabilities {
			if severity == "" {
				severity = vuln.Severity
				cvssv3 = vuln.Cvssv3
				continue
			}
			if severityScore[vuln.Severity] > severityScore[severity] {
				severity = vuln.Severity
				cvssv3 = vuln.Cvssv3
			}
		}

		na := "' not acceptable"
		if attackVector[cvssv3.AttackVector] > attackVector[rules.OwaspDependencyCheck.AcceptableBaseScore.AttackVector] {
			return false, "cvssv3 - attack vector level '" + cvssv3.AttackVector + na, nil
		}
		if attackComplexity[cvssv3.AttackComplexity] > attackComplexity[rules.OwaspDependencyCheck.AcceptableBaseScore.AttackComplexity] {
			return false, "cvssv3 - attack complexity level '" + cvssv3.AttackComplexity + na, nil
		}
		if privilegesRequired[cvssv3.PrivilegesRequired] > privilegesRequired[rules.OwaspDependencyCheck.AcceptableBaseScore.PrivilegesRequired] {
			return false, "cvssv3 - privileges required level '" + cvssv3.PrivilegesRequired + na, nil
		}
		if userInteraction[cvssv3.UserInteraction] > userInteraction[rules.OwaspDependencyCheck.AcceptableBaseScore.UserInteraction] {
			return false, "cvssv3 - user interaction level '" + cvssv3.UserInteraction + na, nil
		}
		if scope[cvssv3.Scope] > scope[rules.OwaspDependencyCheck.AcceptableBaseScore.Scope] {
			return false, "cvssv3 - scope level '" + cvssv3.Scope + na, nil
		}
		if confidentialityImpact[cvssv3.ConfidentialityImpact] > confidentialityImpact[rules.OwaspDependencyCheck.AcceptableBaseScore.ConfidentialityImpact] {
			return false, "cvssv3 - confidentiality impact level '" + cvssv3.ConfidentialityImpact + na, nil
		}
		if integrityImpact[cvssv3.IntegrityImpact] > integrityImpact[rules.OwaspDependencyCheck.AcceptableBaseScore.IntegrityImpact] {
			return false, "cvssv3 - intergrity impact level '" + cvssv3.IntegrityImpact + na, nil
		}
		if availabilityImpact[cvssv3.AvailabilityImpact] > availabilityImpact[rules.OwaspDependencyCheck.AcceptableBaseScore.AvailabilityImpact] {
			return false, "cvssv3 - availability impact level '" + cvssv3.AvailabilityImpact + na, nil
		}

		result[severity]++
	}

	if result["CRITICAL"] > rules.OwaspDependencyCheck.MaxCriticalSeverity {
		return false, "maximum critical cve number exeeded", nil
	}
	if result["HIGH"] > rules.OwaspDependencyCheck.MaxHighSeverity {
		return false, "maximum high cve number exeeded", nil
	}
	if result["MEDIUM"] > rules.OwaspDependencyCheck.MaxMediumServerity {
		return false, "maximum medium cve number exeeded", nil
	}
	if result["LOW"] > rules.OwaspDependencyCheck.MaxCriticalSeverity {
		return false, "maximum low cve number exeeded", nil
	}

	//kubesec
	var kubesecOutput KubesecOutput
	kubesecOuputPath := filepath.Join(folderName, "kubesec-output.json")
	kubesecBytes, err := os.ReadFile(kubesecOuputPath)
	if err != nil {
		logrus.Errorf("error while reading file %s : %w", &kubesecOuputPath, err)
		return false, "error", err
	}

	err = json.Unmarshal(kubesecBytes, &kubesecOutput)
	if err != nil {
		logrus.Errorf("error while unmarshaling file %s : %w", &kubesecOuputPath, err)
		return false, "error", err
	}

	kubesec := false

	for _, mis := range kubesecOutput {
		split := strings.Split(mis.FileName, "/")
		mis.FileName = split[len(split)-1]
		if mis.FileName != filename {
			continue
		} else {
			if mis.Score >= rules.Kubesec.MinScore {
				kubesec = true
			}
			break
		}
	}

	if !kubesec {
		kubesecMsg := "kubesec score is lower than minimum requirement " + string(rune(rules.Kubesec.MinScore))
		return false, kubesecMsg, nil
	}

	return true, "passed", nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func verifyManifest(folderName string, filename string, to map[string]interface{}) (bool, error) {
	var from map[string]interface{}
	filePath := filepath.Join(folderName, "Charts", "templates", filename)

	fromByte, err := os.ReadFile(filePath)
	if err != nil {
		logrus.Errorf("error while reading file %s : %w", filePath, err)
		return false, err
	}

	err = yaml.Unmarshal(fromByte, &from)
	if err != nil {
		logrus.Errorf("error while unmarshaling yaml %s : %w", filePath, err)
		return false, err
	}

	changelog, _ := diff.Diff(from, to)
	for _, log := range changelog {
		if log.Type == "update" || log.Type == "delete" {
			return false, nil
		}
	}

	return true, nil
}

func verifyArtifacts(folderName string) (bool, error) {

	//verify manifest
	inside := folderName + "/Charts/templates/"
	keyFilename := folderName + ".pub"
	keyPath := filepath.Join("public-keys", keyFilename)
	files, err := ioutil.ReadDir(inside)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		full_path := filepath.Join(inside, file.Name())
		verified, err := verify(full_path, "", keyPath, "")
		if err != nil {
			logrus.Infof("error when verifying %s : %w\n", full_path, err)
			return false, err
		}

		if !verified {
			return false, nil
		}
	}

	files, err = ioutil.ReadDir(folderName)
	if err != nil {
		log.Fatal(err)
		return false, err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		err = verifyBlob(folderName, file.Name())
		if err != nil {
			logrus.Errorf("error when verifying %s", file.Name())
			return false, err
		}
	}

	return true, nil
}

func verifyBlob(folderName string, blob string) error {
	filePath := filepath.Join(folderName, blob)
	split := strings.Split(blob, ".")
	signature := split[0] + ".signature"
	signaturePath := filepath.Join(folderName, "blob-signature", signature)
	publicKey := folderName + ".pub"
	keyPath := filepath.Join("public-keys", publicKey)

	securityKey := options.SecurityKeyOptions{
		Use:  false,
		Slot: "",
	}
	rekor := options.RekorOptions{
		URL: "https://rekor.sigstore.dev",
	}
	certVerify := options.CertVerifyOptions{
		Cert:           "",
		CertEmail:      "",
		CertOidcIssuer: "",
		CertChain:      "",
		EnforceSCT:     false,
	}

	tagPrefix := options.ReferenceOptions{
		TagPrefix: "",
	}

	registry := options.RegistryOptions{
		AllowInsecure:      false,
		KubernetesKeychain: false,
		RefOpts:            tagPrefix,
	}
	o := &options.VerifyBlobOptions{
		SecurityKey: securityKey,
		Key:         keyPath,
		Signature:   signaturePath,
		BundlePath:  "",
		CertVerify:  certVerify,
		Rekor:       rekor,
		Registry:    registry,
	}

	ko := sign.KeyOpts{
		KeyRef:     o.Key,
		Sk:         o.SecurityKey.Use,
		Slot:       o.SecurityKey.Slot,
		RekorURL:   o.Rekor.URL,
		BundlePath: o.BundlePath,
	}

	if err := cosign_verify.VerifyBlobCmd(ctx, ko, o.CertVerify.Cert,
		o.CertVerify.CertEmail, o.CertVerify.CertOidcIssuer, o.CertVerify.CertChain,
		o.Signature, filePath, o.CertVerify.EnforceSCT); err != nil {
		return errors.Wrapf(err, "verifying blob %s", filePath)
	}

	return nil
}

func verify(filename, imageRef, keyPath, configPath string) (bool, error) {
	manifest, err := ioutil.ReadFile(filename)
	if err != nil {
		logrus.Errorf(err.Error())
		return false, nil
	}

	vo := &k8smanifest.VerifyManifestOption{}
	if configPath != "" {
		vo, err = k8smanifest.LoadVerifyManifestConfig(configPath)
		if err != nil {
			logrus.Errorf(err.Error())
			return false, nil
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
				diffMsg = fmt.Sprintf("Diff found in %s %s, diffs:%s\n", kind, name, result.Diff.String())
				break
			}
		}
	}
	if verifiedCount == len(objManifests) {
		verified = true
	}
	if verified {
		if signerName == "" {
			logrus.Infof("verified: %s\n", strconv.FormatBool(verified))
		} else {
			logrus.Infof("verified: %s, signerName: %s\n", strconv.FormatBool(verified), signerName)
		}
		return true, nil
	} else {
		errMsg := ""
		if reterr != nil {
			errMsg = reterr.Error()
		} else {
			errMsg = diffMsg
		}
		logrus.Infof("verified: %s, error: %s\n", strconv.FormatBool(verified), errMsg)
		return false, nil
	}
}

func downloadPublicKeyFromStorage(folderName string, gnupId string, bucket string) error {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*50)
	defer cancel()

	client, err := storage.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	destFileName := filepath.Join("public-keys", folderName+".pub")
	object := gnupId + ".pub"

	f, err := os.Create(destFileName)
	if err != nil {
		logrus.Errorf("os.Create: %v", err.Error())
		return err
	}

	rc, err := client.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		logrus.Errorf("Object(%q).NewReader: %v", object, err.Error())
		return err
	}
	defer rc.Close()

	if _, err := io.Copy(f, rc); err != nil {
		logrus.Errorf("io.Copy: %v", err)
	}

	if err = f.Close(); err != nil {
		logrus.Errorf("f.Close: %v", err)
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

func downloadListFromStorage(folderName string, objectList []string, bucket string) error {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*50)
	defer cancel()

	client, err := storage.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	for _, object := range objectList {
		split := strings.Split(object, "/")

		destFileName := filepath.Join(split[1:]...)
		destFileName = filepath.Join(folderName, destFileName)

		if len(split) > 2 {
			path := filepath.Join(split[1 : len(split)-1]...)
			path = filepath.Join(folderName, path)
			if err := os.MkdirAll(path, os.ModePerm); err != nil {
				logrus.Errorf("downloadListFromStorage - %v", err.Error())
				return err
			}
		}

		f, err := os.Create(destFileName)
		if err != nil {
			logrus.Errorf("os.Create: %v", err.Error())
			return err
		}

		rc, err := client.Bucket(bucket).Object(object).NewReader(ctx)
		if err != nil {
			logrus.Errorf("Object(%q).NewReader: %v", object, err.Error())
			return err
		}
		defer rc.Close()

		if _, err := io.Copy(f, rc); err != nil {
			logrus.Errorf("io.Copy: %v", err)
			return err
		}

		if err = f.Close(); err != nil {
			logrus.Errorf("f.Close: %v", err)
			return err
		}

	}
	return nil
}

func getObjectList(prefix string, delim string, bucket string) ([]string, error) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*50)
	defer cancel()

	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var objects []string

	it := client.Bucket(bucket).Objects(ctx, &storage.Query{
		Prefix:    prefix,
		Delimiter: delim,
	})
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Bucket(%q).Objects(): %v", bucket, err)
			return nil, err
		}
		fmt.Fprintln(os.Stdout, attrs.Name)
		objects = append(objects, attrs.Name)
	}

	return objects, nil
}

// reviewResponse TODO: godoc
func reviewResponse(uid types.UID, allowed bool, httpCode int32,
	reason string) *admissionv1.AdmissionReview {
	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1",
		},
		Response: &admissionv1.AdmissionResponse{
			UID:     uid,
			Allowed: allowed,
			Result: &metav1.Status{
				Code:    httpCode,
				Message: reason,
			},
		},
	}
}
