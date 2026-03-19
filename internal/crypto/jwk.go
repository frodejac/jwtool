package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	// Private key fields (optional)
	D string `json:"d,omitempty"`
	// RSA private key CRT parameters
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	Dp string `json:"dp,omitempty"`
	Dq string `json:"dq,omitempty"`
	Qi string `json:"qi,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	// OCT (HMAC)
	K   string `json:"k,omitempty"`
	Ext bool   `json:"ext,omitempty"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// B64urlDecode decodes a base64url-encoded string (no padding).
func B64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// KeyToJWK converts a key to a JWK representation.
func KeyToJWK(k interface{}, includePrivate bool) (JWK, error) {
	switch kt := k.(type) {
	case *rsa.PrivateKey:
		if !includePrivate {
			return rsaPublicToJWK(&kt.PublicKey), nil
		}
		return rsaPrivateToJWK(kt), nil
	case *rsa.PublicKey:
		return rsaPublicToJWK(kt), nil
	case *ecdsa.PrivateKey:
		if !includePrivate {
			return ecPublicToJWK(&kt.PublicKey)
		}
		return ecPrivateToJWK(kt)
	case *ecdsa.PublicKey:
		return ecPublicToJWK(kt)
	case ed25519.PrivateKey:
		if !includePrivate {
			return okpPublicToJWK(kt.Public().(ed25519.PublicKey))
		}
		return okpPrivateToJWK(kt)
	case ed25519.PublicKey:
		return okpPublicToJWK(kt)
	case []byte:
		if !includePrivate {
			return JWK{}, fmt.Errorf("refusing to output symmetric key without --private")
		}
		return JWK{Kty: "OCT", K: base64.RawURLEncoding.EncodeToString(kt)}, nil
	default:
		return JWK{}, fmt.Errorf("unsupported key type")
	}
}

func rsaPublicToJWK(pk *rsa.PublicKey) JWK {
	n := base64.RawURLEncoding.EncodeToString(pk.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(new(big.Int).SetInt64(int64(pk.E)).Bytes())
	return JWK{Kty: "RSA", N: n, E: e}
}

func rsaPrivateToJWK(pk *rsa.PrivateKey) JWK {
	n := base64.RawURLEncoding.EncodeToString(pk.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(new(big.Int).SetInt64(int64(pk.E)).Bytes())
	d := base64.RawURLEncoding.EncodeToString(pk.D.Bytes())
	// Ensure CRT values are computed for dp/dq/qi/oth
	if pk.Precomputed.Dp == nil || pk.Precomputed.Dq == nil || pk.Precomputed.Qinv == nil {
		pk.Precompute()
	}
	var p, q, dp, dq, qi string
	if len(pk.Primes) >= 2 {
		p = base64.RawURLEncoding.EncodeToString(pk.Primes[0].Bytes())
		q = base64.RawURLEncoding.EncodeToString(pk.Primes[1].Bytes())
	}
	if pk.Precomputed.Dp != nil {
		dp = base64.RawURLEncoding.EncodeToString(pk.Precomputed.Dp.Bytes())
	}
	if pk.Precomputed.Dq != nil {
		dq = base64.RawURLEncoding.EncodeToString(pk.Precomputed.Dq.Bytes())
	}
	if pk.Precomputed.Qinv != nil {
		qi = base64.RawURLEncoding.EncodeToString(pk.Precomputed.Qinv.Bytes())
	}
	return JWK{Kty: "RSA", N: n, E: e, D: d, P: p, Q: q, Dp: dp, Dq: dq, Qi: qi}
}

func ecPublicToJWK(pk *ecdsa.PublicKey) (JWK, error) {
	var crv string
	var size int
	switch pk.Curve {
	case elliptic.P256():
		crv = "P-256"
		size = 32
	case elliptic.P384():
		crv = "P-384"
		size = 48
	case elliptic.P521():
		crv = "P-521"
		size = 66 // 521 bits rounded up
	default:
		return JWK{}, fmt.Errorf("unsupported EC curve")
	}
	xb := pk.X.Bytes()
	yb := pk.Y.Bytes()
	if len(xb) < size {
		xb = append(make([]byte, size-len(xb)), xb...)
	}
	if len(yb) < size {
		yb = append(make([]byte, size-len(yb)), yb...)
	}
	x := base64.RawURLEncoding.EncodeToString(xb)
	y := base64.RawURLEncoding.EncodeToString(yb)
	return JWK{Kty: "EC", Crv: crv, X: x, Y: y}, nil
}

func ecPrivateToJWK(pk *ecdsa.PrivateKey) (JWK, error) {
	j, err := ecPublicToJWK(&pk.PublicKey)
	if err != nil {
		return JWK{}, err
	}
	d := base64.RawURLEncoding.EncodeToString(pk.D.Bytes())
	j.D = d
	return j, nil
}

func okpPublicToJWK(pk ed25519.PublicKey) (JWK, error) {
	if len(pk) != ed25519.PublicKeySize {
		return JWK{}, fmt.Errorf("invalid Ed25519 key length")
	}
	x := base64.RawURLEncoding.EncodeToString([]byte(pk))
	return JWK{Kty: "OKP", Crv: "Ed25519", X: x}, nil
}

func okpPrivateToJWK(pk ed25519.PrivateKey) (JWK, error) {
	if len(pk) != ed25519.PrivateKeySize {
		return JWK{}, fmt.Errorf("invalid Ed25519 key length")
	}
	x := base64.RawURLEncoding.EncodeToString(pk.Public().(ed25519.PublicKey))
	d := base64.RawURLEncoding.EncodeToString([]byte(pk.Seed()))
	return JWK{Kty: "OKP", Crv: "Ed25519", X: x, D: d}, nil
}

// ComputeKidForJWK computes a key ID (kid) for the given JWK using SHA-256 thumbprint.
func ComputeKidForJWK(j JWK) (string, error) {
	var thumbBytes []byte

	switch strings.ToUpper(j.Kty) {
	case "RSA":
		type rsaThumb struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}
		thumbBytes, _ = json.Marshal(rsaThumb{E: j.E, Kty: "RSA", N: j.N})
	case "EC":
		type ecThumb struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}
		thumbBytes, _ = json.Marshal(ecThumb{Crv: j.Crv, Kty: "EC", X: j.X, Y: j.Y})
	case "OKP":
		type okpThumb struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}
		thumbBytes, _ = json.Marshal(okpThumb{Crv: j.Crv, Kty: "OKP", X: j.X})
	case "OCT":
		type octThumb struct {
			K   string `json:"k"`
			Kty string `json:"kty"`
		}
		thumbBytes, _ = json.Marshal(octThumb{K: j.K, Kty: "oct"})
	default:
		return "", fmt.Errorf("unsupported kty for kid computation")
	}

	h := sha256.Sum256(thumbBytes)
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// JWKToKey converts a JWK to its corresponding Go key type.
func JWKToKey(j JWK) (interface{}, error) {
	switch strings.ToUpper(j.Kty) {
	case "RSA":
		if j.N == "" || j.E == "" {
			return nil, fmt.Errorf("invalid RSA JWK: missing n or e")
		}
		nBytes, err := B64urlDecode(j.N)
		if err != nil {
			return nil, fmt.Errorf("decode n: %w", err)
		}
		eBytes, err := B64urlDecode(j.E)
		if err != nil {
			return nil, fmt.Errorf("decode e: %w", err)
		}
		n := new(big.Int).SetBytes(nBytes)
		var eInt int
		for _, b := range eBytes {
			eInt = eInt<<8 | int(b)
		}
		return &rsa.PublicKey{N: n, E: eInt}, nil
	case "EC":
		if j.Crv == "" || j.X == "" || j.Y == "" {
			return nil, fmt.Errorf("invalid EC JWK: missing crv/x/y")
		}
		var curve elliptic.Curve
		switch strings.ToUpper(j.Crv) {
		case "P-256", "SECP256R1":
			curve = elliptic.P256()
		case "P-384", "SECP384R1":
			curve = elliptic.P384()
		case "P-521", "SECP521R1":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", j.Crv)
		}
		xb, err := B64urlDecode(j.X)
		if err != nil {
			return nil, fmt.Errorf("decode x: %w", err)
		}
		yb, err := B64urlDecode(j.Y)
		if err != nil {
			return nil, fmt.Errorf("decode y: %w", err)
		}
		x := new(big.Int).SetBytes(xb)
		y := new(big.Int).SetBytes(yb)
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		if strings.EqualFold(j.Crv, "Ed25519") {
			xb, err := B64urlDecode(j.X)
			if err != nil {
				return nil, fmt.Errorf("decode x: %w", err)
			}
			if l := len(xb); l != ed25519.PublicKeySize {
				return nil, fmt.Errorf("invalid Ed25519 key length: %d", l)
			}
			return ed25519.PublicKey(xb), nil
		}
		return nil, fmt.Errorf("unsupported OKP curve: %s", j.Crv)
	case "OCT":
		if j.K == "" {
			return nil, fmt.Errorf("invalid oct JWK: missing k")
		}
		kb, err := B64urlDecode(j.K)
		if err != nil {
			return nil, fmt.Errorf("decode k: %w", err)
		}
		return kb, nil
	default:
		return nil, fmt.Errorf("unsupported kty: %s", j.Kty)
	}
}

// LoadKeyFromJWKSRaw loads a verification key from a JWKS reference,
// matching by kid if provided.
func LoadKeyFromJWKSRaw(ref string, kid string) (interface{}, error) {
	data, err := ReadRef(ref)
	if err != nil {
		return nil, err
	}
	var set JWKS
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	var selected *JWK
	if kid != "" {
		for i := range set.Keys {
			if set.Keys[i].Kid == kid {
				selected = &set.Keys[i]
				break
			}
		}
		if selected == nil {
			return nil, fmt.Errorf("no JWK with kid %q found", kid)
		}
	} else {
		if len(set.Keys) == 1 {
			selected = &set.Keys[0]
		} else {
			return nil, fmt.Errorf("multiple keys in JWKS and token has no kid")
		}
	}

	return JWKToKey(*selected)
}
