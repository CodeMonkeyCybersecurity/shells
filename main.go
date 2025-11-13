package main

import (
	"os"

	"github.com/CodeMonkeyCybersecurity/artemis/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
