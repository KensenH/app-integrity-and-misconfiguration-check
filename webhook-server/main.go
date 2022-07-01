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
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/simple-kubernetes-webhook/pkg/admission"
	"google.golang.org/api/iterator"

	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	types "k8s.io/apimachinery/pkg/types"
)

const letterBytes = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

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
	fmt.Fprint(w, "OK")
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

// ServeMutatePods returns an admission review with pod mutations as a json patch
// in the review response
func ServeMutatePods(w http.ResponseWriter, r *http.Request) {
	logger := logrus.WithField("uri", r.RequestURI)
	logger.Debug("received mutation request")

	in, err := parseRequest(*r)
	if err != nil {
		logger.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	adm := admission.Admitter{
		Logger:  logger,
		Request: in.Request,
	}

	out, err := adm.MutatePodReview()
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
	if namespace != "default" {
		return reviewResponse(in.Request.UID, true, http.StatusAccepted, "namespace not default"), err
	}

	//check if resource have parent, if yes then approve
	if _, ok := objMetadata["ownerReferences"]; ok {
		return reviewResponse(in.Request.UID, true, http.StatusAccepted, "child resource"), err
	}

	//check if there is cosign signature and gnup-id
	objAnnotations := objMetadata["annotations"].(map[string]interface{})
	if _, ok := objAnnotations["cosign.sigstore.dev/message"]; !ok {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "signature/message annotation not found"), err
	}
	if _, ok := objAnnotations["cosign.sigstore.dev/signature"]; !ok {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "signature/signature annotation not found"), err
	}
	if _, ok := objAnnotations["gnup-id"]; !ok {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "gnup-id annotation not found"), err
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
	objectList, err := getObjectList(gnupId[0]+"_artifacts/", "", "gather-n-upload-artifacts")
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "listing object failed"), err
	}

	err = downloadListFromStorage(folderName, objectList, "gather-n-upload-artifacts")
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "downloading list from storage failed"), err
	}

	err = downloadPublicKeyFromStorage(folderName, gnupId[0], "gather-n-upload-public-keys")
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "downloading public key from storage failed: "), err
	}

	verified, err := verifyArtifacts()
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "verifying process failed"), err
	}

	rulesMatch, err := rulesValidation()
	if err != nil {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "rules matching failed"), err
	}

	if verified == false && rulesMatch == false {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "integrity not valid dan doesn't match rules"), err
	} else if verified == true && rulesMatch == false {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "integrity valid but doesn't match rules"), err
	} else if verified == false && rulesMatch == true {
		return reviewResponse(in.Request.UID, false, http.StatusAccepted, "integrity not valid"), err
	}

	return reviewResponse(in.Request.UID, true, http.StatusAccepted, ""), err
}

func clean() error {

	return nil
}

func rulesValidation() (bool, error) {

	return true, nil
}

func verifyArtifacts() (bool, error) {

	return true, nil
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
	logrus.Debug("annotations", annotations)
	logrus.Debug("imageRef", imageRef)

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
			logrus.Infof("verifed: %s", strconv.FormatBool(verified))
		} else {
			logrus.Infof("verifed: %s, signerName: %s", strconv.FormatBool(verified), signerName)
		}
	} else {
		errMsg := ""
		if reterr != nil {
			errMsg = reterr.Error()
		} else {
			errMsg = diffMsg
		}
		logrus.Fatalf("verifed: %s, error: %s", strconv.FormatBool(verified), errMsg)
	}

	return nil
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
		log.Fatalf("os.Create: %v", err.Error())
	}

	rc, err := client.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		log.Fatalf("Object(%q).NewReader: %v", object, err.Error())
	}
	defer rc.Close()

	if _, err := io.Copy(f, rc); err != nil {
		log.Fatalf("io.Copy: %v", err)
	}

	if err = f.Close(); err != nil {
		log.Fatalf("f.Close: %v", err)
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
				log.Fatal(err)
			}
		}

		f, err := os.Create(destFileName)
		if err != nil {
			log.Fatalf("os.Create: %v", err.Error())
		}

		rc, err := client.Bucket(bucket).Object(object).NewReader(ctx)
		if err != nil {
			log.Fatalf("Object(%q).NewReader: %v", object, err.Error())
		}
		defer rc.Close()

		if _, err := io.Copy(f, rc); err != nil {
			log.Fatalf("io.Copy: %v", err)
		}

		if err = f.Close(); err != nil {
			log.Fatalf("f.Close: %v", err)
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
