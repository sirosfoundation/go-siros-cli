// Package main is the entry point for the wallet-cli application.package walletcli

package main

import (
	"os"

	"github.com/sirosfoundation/go-siros-cli/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
