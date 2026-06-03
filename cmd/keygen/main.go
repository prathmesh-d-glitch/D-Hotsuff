// Command keygen generates ECDSA P-256 key pairs for D-HotStuff replicas
// and prints a ready-to-paste genesis.toml [[replicas]] snippet.
//
// Usage:
//
//	keygen [--n <int>] [--out <dir>] [--prefix <string>]
//
// Flags:
//
//	--n       number of key pairs to generate (default 4)
//	--out     output directory for private-key PEM files (default ./keys)
//	--prefix  filename and ID prefix (default P)
//
// For each replica i (1..n) the tool:
//  1. Generates a fresh ECDSA P-256 private key.
//  2. Marshals it to PKCS #8 DER bytes and PEM-encodes the result.
//  3. Writes the PEM file to {out}/{prefix}{i}.key with mode 0600.
//  4. Marshals the corresponding public key to PKIX (SubjectPublicKeyInfo)
//     DER bytes and base64-encodes them (standard encoding, no line breaks).
//  5. Prints a [[replicas]] TOML block to stdout.
//
// After all replicas are processed a complete genesis.toml snippet is printed
// that can be copied directly into config/genesis.toml.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	n := flag.Int("n", 4, "number of key pairs to generate")
	out := flag.String("out", "./keys", "output directory for private-key PEM files")
	prefix := flag.String("prefix", "P", "filename and replica-ID prefix")
	flag.Parse()

	if *n < 1 {
		log.Fatal("--n must be >= 1")
	}

	// Ensure the output directory exists.
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatalf("create output directory %q: %v", *out, err)
	}

	// Buffer the TOML snippet so we can print it as one block at the end.
	var sb strings.Builder

	fmt.Fprintln(&sb, "# genesis.toml — paste the section below into config/genesis.toml")
	fmt.Fprintln(&sb, "[committee]")
	fmt.Fprintln(&sb, "config_number = 0")
	fmt.Fprintln(&sb)

	for i := 1; i <= *n; i++ {
		id := fmt.Sprintf("%s%d", *prefix, i)

		// 1. Generate ECDSA P-256 private key.
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("replica %s: generate key: %v", id, err)
		}

		// 2. Marshal private key → PKCS #8 DER → PEM.
		privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			log.Fatalf("replica %s: marshal private key: %v", id, err)
		}
		privPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privDER,
		})

		// 3. Write private-key PEM to {out}/{id}.key (mode 0600).
		keyPath := filepath.Join(*out, id+".key")
		if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
			log.Fatalf("replica %s: write key file %q: %v", id, keyPath, err)
		}
		log.Printf("wrote private key → %s", keyPath)

		// 4. Marshal public key → PKIX DER → base64.
		pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		if err != nil {
			log.Fatalf("replica %s: marshal public key: %v", id, err)
		}
		pubB64 := base64.StdEncoding.EncodeToString(pubDER)

		// 5. Append [[replicas]] TOML block.
		fmt.Fprintf(&sb, "[[replicas]]\n")
		fmt.Fprintf(&sb, "id      = %q\n", id)
		fmt.Fprintf(&sb, "address = \"127.0.0.1:800%d\"\n", i)
		fmt.Fprintf(&sb, "pubkey  = %q\n", pubB64)
		fmt.Fprintln(&sb)
	}

	// Print the complete genesis.toml snippet.
	fmt.Print(sb.String())
}
