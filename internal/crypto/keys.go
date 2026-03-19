package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ParsePEMBlock parses a single PEM block into a key or certificate public key.
func ParsePEMBlock(block *pem.Block) (interface{}, error) {
	t := strings.ToUpper(block.Type)
	switch t {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		switch pk := cert.PublicKey.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			return pk, nil
		default:
			return nil, nil
		}
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		switch pk := pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			return pk, nil
		default:
			return nil, fmt.Errorf("unsupported public key type")
		}
	case "RSA PUBLIC KEY":
		pk, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA public key: %w", err)
		}
		return pk, nil
	case "EC PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC public key: %w", err)
		}
		epk, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an ECDSA public key")
		}
		return epk, nil
	case "PRIVATE KEY": // PKCS#8
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key (PKCS#8): %w", err)
		}
		switch p := priv.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return p, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS#8 private key type")
		}
	case "RSA PRIVATE KEY":
		p, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA private key: %w", err)
		}
		return p, nil
	case "EC PRIVATE KEY":
		p, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		return p, nil
	default:
		// Best-effort: try PKIX
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			switch pk := pub.(type) {
			case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
				return pk, nil
			}
		}
		return nil, nil
	}
}

// ParseKeysFromInput reads the input file. If it's PEM, it parses all blocks and
// returns the key(s). If not PEM, treats the content as a raw octet key.
func ParseKeysFromInput(path string) ([]interface{}, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	s := string(b)
	if strings.Contains(s, "-----BEGIN ") {
		var keys []interface{}
		rest := b
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			// Reject encrypted private keys explicitly
			if strings.Contains(strings.ToUpper(block.Type), "ENCRYPTED") {
				return nil, fmt.Errorf("encrypted private keys are not supported")
			}
			k, err := ParsePEMBlock(block)
			if err != nil {
				return nil, err
			}
			if k != nil {
				keys = append(keys, k)
			}
		}
		return keys, nil
	}
	// Not PEM: treat as raw secret (HS*) bytes
	return []interface{}{b}, nil
}

// ReadRef reads data from a URL (http/https) or file path.
func ReadRef(ref string) ([]byte, error) {
	u, err := url.Parse(ref)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(ref)
		if err != nil {
			return nil, fmt.Errorf("fetch JWKS: %w", err)
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: error closing response body: %s\n", err)
			}
		}(resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("fetch JWKS: HTTP %d", resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read JWKS: %w", err)
		}
		return b, nil
	}
	// Fallback to file path
	b, err := os.ReadFile(ref)
	if err != nil {
		return nil, fmt.Errorf("read JWKS file: %w", err)
	}
	return b, nil
}

// NewJti generates a random JWT ID.
func NewJti() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
