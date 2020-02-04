package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// GenerateRsaKeyPair generates a new RSA private/public key pair
func GenerateRsaKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, bits)
	return privkey, &privkey.PublicKey
}

// ExportRsaPrivateKeyAsPemStr writes the given private key to a PEM encoded file
// as used by sshd et. al.
func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return string(privkeyPem)
}

// ParseRsaPrivateKeyFromPemStr parses the given PEM encoded string into a go rsa key.
func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// ExportRsaPublicKeyAsPemStr exports the public key as PEM encoded string
func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) string {
	// err can never be non-nil at this point, as marshalPKIXPublicKey only throws on unknown keys
	// whereas rsa.PublicKey is well-known
	pubkeyBytes := x509.MarshalPKCS1PublicKey(pubkey)
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)

	return string(pubkeyPem)
}

// ExportPubKeyBase64 converts a RSA Public key into the base64 representation
func ExportPubKeyBase64(pubkey *rsa.PublicKey) string {
	pubkeyBytes := x509.MarshalPKCS1PublicKey(pubkey)
	return base64.StdEncoding.EncodeToString(pubkeyBytes)
}

// ParseRsaPublicKeyFromPemStr parses the given PEM encoded string into a go rsa key.
func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}
