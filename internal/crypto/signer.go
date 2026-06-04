// Package crypto provides ECDSA P-256 signing and verification primitives for
// the D-HotStuff BFT consensus protocol.
//
// Uses raw ECDSA signatures instead of threshold signatures because DPSS
// (Proactive Secret Sharing) in partial synchrony costs O(n^3) per the
// D-HotStuff paper §4.1.  At committee sizes nc <= ~200 the O(n^2)
// per-round cost of broadcasting individual ECDSA signatures is substantially
// cheaper than any re-sharing round.
//
// # Signature format
//
// Sign and Verify use a compact 64-byte fixed-width encoding:
//
//	sig[0:32]  = r, zero-padded big-endian (P-256 field element, 32 bytes)
//	sig[32:64] = s, zero-padded big-endian (P-256 field element, 32 bytes)
//
// This avoids ASN.1/DER variable-length overhead and simplifies concatenation
// into QuorumCert.Signatures slices.
//
// # Message format
//
// Per §6.1 of the D-HotStuff paper, the signed message is:
//
//	SHA-256( view_number_BE_8 || conf_number_BE_8 || block_hash )
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

// p256FieldBytes is the byte width of a P-256 field element (256 bits / 8).
const p256FieldBytes = 32

// signatureLen is the fixed length of a D-HotStuff ECDSA signature: r || s.
const signatureLen = p256FieldBytes * 2

// Sign produces a 64-byte ECDSA P-256 signature over the tuple
// (viewNum, confNum, blockHash) as specified in D-HotStuff §6.1.
//
// The message digest is:
//
//	SHA-256( view_num_BE_8 || conf_num_BE_8 || blockHash )
//
// The returned signature is 64 bytes: r zero-padded to 32 bytes followed by
// s zero-padded to 32 bytes.
func Sign(privKey *ecdsa.PrivateKey, viewNum, confNum uint64, blockHash []byte) ([]byte, error) {
	digest := hashTuple(viewNum, confNum, blockHash)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("crypto.Sign: %w", err)
	}

	return encodeRS(r, s), nil
}

// Verify reports whether sig is a valid D-HotStuff signature over
// (viewNum, confNum, blockHash) produced with the private key corresponding
// to pubKey.
//
// sig must be exactly 64 bytes (r || s, each zero-padded to 32 bytes).
// Returns false for any malformed input rather than propagating an error, so
// callers can treat it as a simple boolean predicate.
func Verify(pubKey *ecdsa.PublicKey, viewNum, confNum uint64, blockHash, sig []byte) bool {
	if len(sig) != signatureLen {
		return false
	}

	digest := hashTuple(viewNum, confNum, blockHash)
	r, s := decodeRS(sig)

	return ecdsa.Verify(pubKey, digest[:], r, s)
}

// LoadPrivateKey reads a PKCS #8 PEM-encoded ECDSA private key from path and
// returns the parsed key.  The file must contain exactly one PEM block of type
// "PRIVATE KEY" (the format written by cmd/keygen).
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
// der is typically the base64-decoded value of a pubkey field from genesis.toml.
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

// PublicKeyToDER encodes pub as PKIX (SubjectPublicKeyInfo) DER bytes.
// The result is suitable for base64 encoding into genesis.toml or embedding
// in a MembershipRequest.Payload for an ADD command.
func PublicKeyToDER(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("crypto.PublicKeyToDER: %w", err)
	}
	return der, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// hashTuple returns SHA-256( viewNum_BE8 || confNum_BE8 || blockHash ).
func hashTuple(viewNum, confNum uint64, blockHash []byte) [sha256.Size]byte {
	var buf [16]byte
	// viewNum big-endian 8 bytes
	buf[0] = byte(viewNum >> 56)
	buf[1] = byte(viewNum >> 48)
	buf[2] = byte(viewNum >> 40)
	buf[3] = byte(viewNum >> 32)
	buf[4] = byte(viewNum >> 24)
	buf[5] = byte(viewNum >> 16)
	buf[6] = byte(viewNum >> 8)
	buf[7] = byte(viewNum)
	// confNum big-endian 8 bytes
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

// encodeRS packs (r, s) into a fixed 64-byte slice, zero-padding each to 32 bytes.
func encodeRS(r, s *big.Int) []byte {
	sig := make([]byte, signatureLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	// Right-align within each 32-byte half (zero-pad on the left).
	copy(sig[p256FieldBytes-len(rBytes):p256FieldBytes], rBytes)
	copy(sig[signatureLen-len(sBytes):signatureLen], sBytes)
	return sig
}

// decodeRS unpacks the 64-byte fixed-width signature back into big.Int r, s.
func decodeRS(sig []byte) (r, s *big.Int) {
	r = new(big.Int).SetBytes(sig[:p256FieldBytes])
	s = new(big.Int).SetBytes(sig[p256FieldBytes:])
	return r, s
}

// ErrNotECDSA is a typed sentinel used by LoadPrivateKey / LoadPublicKey when
// the parsed key is not an ECDSA key.
var ErrNotECDSA = errors.New("crypto: key is not an ECDSA key")
