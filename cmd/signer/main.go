package main

import (
	"os"
	"runtime/debug"
	"signer/cli"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/util"
)

func init() {
	// util.GitVersion is automatically set by `make build` command usually.
	// However, it will be a default value "develop" in case of `go install`,
	// so get values by debug.ReadBuildInfo() here.
	if util.GitVersion == "develop" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			util.GitVersion = bi.Main.Version
		}
	}
}

func main() {
	if err := cli.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
