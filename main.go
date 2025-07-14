package main

import (
	"os"

	"github.com/yourusername/shells/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}