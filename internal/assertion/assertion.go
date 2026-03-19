package assertion

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/frodejac/jwtool/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

// Config holds the configuration for the assertion command.
type Config struct {
	ClientID       string
	Audience       string
	PrivateKeyPath string
	Kid            string
}

// Run executes the assertion command.
func Run(cfg Config, stdout, stderr io.Writer) error {
	if cfg.ClientID == "" || cfg.Audience == "" || cfg.PrivateKeyPath == "" {
		return fmt.Errorf("--clientid, --audience, and --privatekey are required")
	}

	key, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("Error reading private key: %s", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return fmt.Errorf("Error parsing private key: %s", err)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Minute)
	jti, err := crypto.NewJti()
	if err != nil {
		return fmt.Errorf("Error generating jti: %s", err)
	}
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.MapClaims{
			"iss": cfg.ClientID,
			"sub": cfg.ClientID,
			"nbf": now.Unix(),
			"iat": now.Unix(),
			"exp": expires.Unix(),
			"jti": jti,
			"aud": cfg.Audience,
		})
	token.Header["typ"] = "client-authentication+jwt"
	if cfg.Kid != "" {
		token.Header["kid"] = cfg.Kid
	}
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return fmt.Errorf("Error signing token: %s", err)
	}
	fmt.Fprintln(stdout, tokenString)
	return nil
}
