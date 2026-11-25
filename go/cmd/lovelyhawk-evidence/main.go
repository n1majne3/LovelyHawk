package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/n1majne3/LovelyHawk/go/internal/evidence"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	if len(args) != 2 || args[0] != "verify" {
		fmt.Fprintln(errOut, "usage: lovelyhawk-evidence verify <bundle-directory>")
		return 2
	}
	result, err := evidence.Verify(args[1])
	if err != nil {
		fmt.Fprintln(errOut, err)
		if errors.Is(err, evidence.ErrMismatch) {
			return 1
		}
		return 2
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	return 0
}
