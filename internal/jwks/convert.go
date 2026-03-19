package jwks

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/frodejac/jwtool/internal/crypto"
)

// Config holds the configuration for the jwks command.
type Config struct {
	InPath    string
	OutPath   string
	Alg       string
	Use       string
	Kid       string
	Private   bool
	Ext       bool
	UglyPrint bool
}

// Run executes the jwks conversion command.
func Run(cfg Config, stdout, stderr io.Writer) error {
	if cfg.InPath == "" {
		return fmt.Errorf("-in is required")
	}

	items, err := crypto.ParseKeysFromInput(cfg.InPath)
	if err != nil {
		return fmt.Errorf("Error reading input: %s", err)
	}
	if len(items) == 0 {
		return fmt.Errorf("No supported keys found in input")
	}
	if cfg.Kid != "" && len(items) > 1 {
		return fmt.Errorf("--kid is only allowed when exactly one key is present")
	}

	outSet := crypto.JWKS{Keys: make([]crypto.JWK, 0, len(items))}
	for _, k := range items {
		j, err := crypto.KeyToJWK(k, cfg.Private)
		if err != nil {
			return fmt.Errorf("Key conversion error: %s", err)
		}
		if cfg.Alg != "" {
			j.Alg = cfg.Alg
		}
		if cfg.Use != "" {
			j.Use = cfg.Use
		}
		if cfg.Kid != "" {
			j.Kid = cfg.Kid
		} else {
			if kid, err := crypto.ComputeKidForJWK(j); err == nil {
				j.Kid = kid
			}
		}
		if cfg.Ext {
			j.Ext = true
		}
		outSet.Keys = append(outSet.Keys, j)
	}

	var data []byte
	if cfg.UglyPrint {
		data, err = json.Marshal(outSet)
	} else {
		data, err = json.MarshalIndent(outSet, "", "  ")
	}
	if err != nil {
		return fmt.Errorf("JWKS marshal error: %s", err)
	}

	if cfg.OutPath == "" {
		fmt.Fprintln(stdout, string(data))
		return nil
	}
	if err := os.WriteFile(cfg.OutPath, data, 0600); err != nil {
		return fmt.Errorf("Write JWKS: %s", err)
	}
	return nil
}
