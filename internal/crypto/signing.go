package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// SigningMethodFromAlg returns the jwt.SigningMethod for the given algorithm string.
func SigningMethodFromAlg(alg string) (jwt.SigningMethod, error) {
	switch strings.ToUpper(alg) {
	case "HS256":
		return jwt.SigningMethodHS256, nil
	case "HS384":
		return jwt.SigningMethodHS384, nil
	case "HS512":
		return jwt.SigningMethodHS512, nil
	case "RS256":
		return jwt.SigningMethodRS256, nil
	case "RS384":
		return jwt.SigningMethodRS384, nil
	case "RS512":
		return jwt.SigningMethodRS512, nil
	case "ES256":
		return jwt.SigningMethodES256, nil
	case "ES384":
		return jwt.SigningMethodES384, nil
	case "ES512":
		return jwt.SigningMethodES512, nil
	case "EDDSA":
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// LoadSigningKey loads and validates a signing key for the given algorithm.
func LoadSigningKey(alg, keyPath string) (interface{}, error) {
	keys, err := ParseKeysFromInput(keyPath)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found in %s", keyPath)
	}
	key := keys[0]

	a := strings.ToUpper(alg)
	switch {
	case strings.HasPrefix(a, "HS"):
		if b, ok := key.([]byte); ok {
			return b, nil
		}
		return nil, fmt.Errorf("HMAC algorithms require a raw secret key, got %T", key)
	case strings.HasPrefix(a, "RS"):
		if pk, ok := key.(*rsa.PrivateKey); ok {
			return pk, nil
		}
		return nil, fmt.Errorf("RSA algorithms require an *rsa.PrivateKey, got %T", key)
	case strings.HasPrefix(a, "ES"):
		if pk, ok := key.(*ecdsa.PrivateKey); ok {
			return pk, nil
		}
		return nil, fmt.Errorf("EC algorithms require an *ecdsa.PrivateKey, got %T", key)
	case a == "EDDSA":
		if pk, ok := key.(ed25519.PrivateKey); ok {
			return pk, nil
		}
		return nil, fmt.Errorf("EdDSA requires an ed25519.PrivateKey, got %T", key)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// LoadVerifyKey loads a verification key for the given algorithm.
func LoadVerifyKey(alg string, keyPath string) (interface{}, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	a := strings.ToUpper(alg)
	switch a {
	case "HS256", "HS384", "HS512":
		return data, nil // raw secret bytes
	case "RS256", "RS384", "RS512":
		if pub, err := jwt.ParseRSAPublicKeyFromPEM(data); err == nil {
			return pub, nil
		}
		if priv, err := jwt.ParseRSAPrivateKeyFromPEM(data); err == nil {
			return &priv.PublicKey, nil
		}
		return nil, fmt.Errorf("unable to parse RSA key from PEM")
	case "ES256", "ES384", "ES512":
		if pub, err := jwt.ParseECPublicKeyFromPEM(data); err == nil {
			return pub, nil
		}
		if priv, err := jwt.ParseECPrivateKeyFromPEM(data); err == nil {
			return &priv.PublicKey, nil
		}
		return nil, fmt.Errorf("unable to parse EC key from PEM")
	case "EDDSA":
		if pub, err := jwt.ParseEdPublicKeyFromPEM(data); err == nil {
			return pub, nil
		}
		if priv, err := jwt.ParseEdPrivateKeyFromPEM(data); err == nil {
			key, ok := priv.(ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not an Ed25519 private key")
			}
			return key.Public(), nil
		}
		return nil, fmt.Errorf("unable to parse Ed25519 key from PEM")
	default:
		return nil, fmt.Errorf("unsupported alg: %s", alg)
	}
}
