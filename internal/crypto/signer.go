// Package crypto provides ECDSA P-256 signing and verification for D-HotStuff.
// Signature format: 64 bytes = r (32 bytes) || s (32 bytes), both big-endian.
// Signed message: SHA-256(view_BE8 || conf_BE8 || blockHash).
package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

const p256FieldBytes = 32
const signatureLen = p256FieldBytes * 2

// Sign produces a 64-byte ECDSA P-256 signature over (viewNum, confNum, blockHash).
func Sign(privKey *ecdsa.PrivateKey, viewNum, confNum uint64, blockHash []byte) ([]byte, error) {
	digest := hashTuple(viewNum, confNum, blockHash)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("crypto.Sign: %w", err)
	}

	return encodeRS(r, s), nil
}

// Verify checks whether sig is a valid signature over (viewNum, confNum, blockHash).
// Returns false for any malformed input.
func Verify(pubKey *ecdsa.PublicKey, viewNum, confNum uint64, blockHash, sig []byte) bool {
	if len(sig) != signatureLen {
		return false
	}

	digest := hashTuple(viewNum, confNum, blockHash)
	r, s := decodeRS(sig)

	return ecdsa.Verify(pubKey, digest[:], r, s)
}

// LoadPrivateKey reads a PKCS#8 PEM-encoded ECDSA key from path.
func LoadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto.LoadPrivateKey: read %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto.LoadPrivateKey: %q: no PEM block found", path)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto.LoadPrivateKey: parse PKCS8 from %q: %w", path, err)
	}

	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto.LoadPrivateKey: %q: expected *ecdsa.PrivateKey, got %T", path, parsed)
	}

	return ecKey, nil
}

// LoadPublicKey parses a PKIX DER-encoded ECDSA P-256 public key.
func LoadPublicKey(der []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("crypto.LoadPublicKey: parse PKIX: %w", err)
	}

	ecKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("crypto.LoadPublicKey: expected *ecdsa.PublicKey, got %T", parsed)
	}

	return ecKey, nil
}

// PublicKeyToDER encodes pub as PKIX DER bytes (for genesis.toml or ADD payloads).
func PublicKeyToDER(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("crypto.PublicKeyToDER: %w", err)
	}
	return der, nil
}

// hashTuple returns SHA-256(viewNum_BE8 || confNum_BE8 || blockHash).
func hashTuple(viewNum, confNum uint64, blockHash []byte) [sha256.Size]byte {
	var buf [16]byte
	buf[0] = byte(viewNum >> 56)
	buf[1] = byte(viewNum >> 48)
	buf[2] = byte(viewNum >> 40)
	buf[3] = byte(viewNum >> 32)
	buf[4] = byte(viewNum >> 24)
	buf[5] = byte(viewNum >> 16)
	buf[6] = byte(viewNum >> 8)
	buf[7] = byte(viewNum)
	buf[8] = byte(confNum >> 56)
	buf[9] = byte(confNum >> 48)
	buf[10] = byte(confNum >> 40)
	buf[11] = byte(confNum >> 32)
	buf[12] = byte(confNum >> 24)
	buf[13] = byte(confNum >> 16)
	buf[14] = byte(confNum >> 8)
	buf[15] = byte(confNum)

	h := sha256.New()
	h.Write(buf[:])
	h.Write(blockHash)

	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// encodeRS packs (r, s) into a fixed 64-byte slice, zero-padded to 32 bytes each.
func encodeRS(r, s *big.Int) []byte {
	sig := make([]byte, signatureLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[p256FieldBytes-len(rBytes):p256FieldBytes], rBytes)
	copy(sig[signatureLen-len(sBytes):signatureLen], sBytes)
	return sig
}

// decodeRS unpacks the 64-byte signature into big.Int r and s.
func decodeRS(sig []byte) (r, s *big.Int) {
	r = new(big.Int).SetBytes(sig[:p256FieldBytes])
	s = new(big.Int).SetBytes(sig[p256FieldBytes:])
	return r, s
}

// ErrNotECDSA is returned when a loaded key is not an ECDSA key.
var ErrNotECDSA = errors.New("crypto: key is not an ECDSA key")
