package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

func main() {
	bucket := "gather-n-upload-artifacts"

	objectList, err := getObjectList("F29TECs0OfvINuz_artifacts/", "", bucket)
	if err != nil {
		log.Fatalf("listing object failed : %t", err)
	}

	err = downloadListFromStorage(objectList, bucket)
	if err != nil {
		log.Fatalf("error while downloading item from object list : %t", err)
	}

}

func downloadListFromStorage(objectList []string, bucket string) error {
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
		path := filepath.Join(split[1 : len(split)-1]...)
		destFileName := filepath.Join(split[1:]...)

		if len(split) > 2 {
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

		fmt.Fprintf(os.Stdout, "Blob %v downloaded to local file %v\n", object, destFileName)
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
