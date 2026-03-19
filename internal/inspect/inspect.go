package inspect

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/frodejac/jwtool/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

// Config holds the configuration for the inspect command.
type Config struct {
	IncludeHeaders bool
	UglyPrint      bool
	VerifySig      bool
	VerifyKeyPath  string
	JWKSRef        string
	Token          string
}

// Run executes the inspect command.
func Run(cfg Config, stdout, stderr io.Writer) error {
	jwtString := strings.TrimSpace(cfg.Token)

	var token *jwt.Token
	var err error
	token, err = jwt.Parse(jwtString, nil)
	if err != nil {
		if !errors.Is(err, jwt.ErrTokenUnverifiable) {
			return fmt.Errorf("Error parsing JWT: %s", err)
		}
	}

	if cfg.VerifySig {
		if cfg.VerifyKeyPath == "" && cfg.JWKSRef == "" {
			return fmt.Errorf("--verify requires --key or --jwks to be provided")
		}
		if cfg.VerifyKeyPath != "" && cfg.JWKSRef != "" {
			return fmt.Errorf("--key and --jwks are mutually exclusive")
		}
		alg, ok := token.Header["alg"].(string)
		if !ok || alg == "" {
			return fmt.Errorf("Cannot determine alg from token header")
		}
		var key interface{}
		var err error
		if cfg.JWKSRef != "" {
			kid, _ := token.Header["kid"].(string)
			k, kerr := crypto.LoadKeyFromJWKSRaw(cfg.JWKSRef, kid)
			if kerr != nil {
				return fmt.Errorf("Error loading key from JWKS: %s", kerr)
			}
			key = k
		} else {
			key, err = crypto.LoadVerifyKey(alg, cfg.VerifyKeyPath)
		}
		if err != nil {
			return fmt.Errorf("Error loading verification key: %s", err)
		}
		token, err = jwt.Parse(jwtString, func(t *jwt.Token) (interface{}, error) { return key, nil }, jwt.WithValidMethods([]string{alg}), jwt.WithoutClaimsValidation())
		if err != nil {
			return fmt.Errorf("Signature verification failed: %s", err)
		}
		if !token.Valid {
			return fmt.Errorf("Signature verification failed: token invalid")
		}
	}

	if cfg.IncludeHeaders {
		fmt.Fprintln(stdout, format(token.Header, cfg.UglyPrint, stderr))
	}
	fmt.Fprintln(stdout, format(token.Claims, cfg.UglyPrint, stderr))
	return nil
}

func format(v interface{}, ugly bool, stderr io.Writer) string {
	var out []byte
	var err error
	if ugly {
		out, err = json.Marshal(v)
	} else {
		out, err = json.MarshalIndent(v, "", "  ")
	}
	if err != nil {
		fmt.Fprintf(stderr, "marshalling error: %s\n", err)
		return ""
	}
	return string(out)
}
