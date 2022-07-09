package cmd

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/storage"

	log "github.com/sirupsen/logrus"
)

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

func uploadPublicKey(id string, bucketname string) error {
	err := uploadFileToBackendStorage("./cosign.pub", bucketname, id+".pub")
	if err != nil {
		log.Errorf("upload public key error")
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
