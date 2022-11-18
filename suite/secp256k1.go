// The AGPLv3 License (AGPLv3)

// Copyright (c) 2022 ZHAO Zhenhua <zhao.zhenhua@gmail.com>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package suite

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

type Secp256k1PrivateKey struct {
	privKey *ecdsa.PrivateKey
}

func (s *Secp256k1PrivateKey) PublicKey() (PublicKey, error) {
	pubKey := &Secp256k1PublicKey{pubKey: &s.privKey.PublicKey}
	return pubKey, nil
}

func (s *Secp256k1PrivateKey) Verify(k Key, signature []byte, digest []byte) (bool, error) {
	b, _ := k.(*Secp256k1PublicKey).Bytes()
	return crypto.VerifySignature(b, digest, signature), nil
}

// Sign signs a message's hash
func (s *Secp256k1PrivateKey) Sign(k Key, digest []byte) ([]byte, error) {
	return crypto.Sign(digest, k.(*Secp256k1PrivateKey).privKey)
}

func (s *Secp256k1PrivateKey) Encrypt(k Key, plaintext []byte) ([]byte, error) {
	return nil, errors.New("Secp256k1 dose not support encrypt")
}

func (s *Secp256k1PrivateKey) Decrypt(k Key, ciphertext []byte) ([]byte, error) {
	return nil, errors.New("Secp256k1 dose not support encrypt")
}

// Algorithm returns the corresponding algorithm
func (s *Secp256k1PrivateKey) Algorithm() string {
	return SECP256K1
}

func (s *Secp256k1PrivateKey) String() string {
	return string(crypto.FromECDSA(s.privKey))
}

type Secp256k1KeyPair struct {
	privKey Secp256k1PrivateKey
	pubKey  Secp256k1PublicKey
}

func (s *Secp256k1KeyPair) GetKeyPair() (PrivateKey, PublicKey, error) {
	return &s.privKey, &s.pubKey, nil
}

func (s *Secp256k1KeyPair) Algorithm() string {
	return SECP256K1
}

func GenSignKeyPair() (PrivateKey, PublicKey, error) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	pubKey := privKey.PublicKey
	return &Secp256k1PrivateKey{privKey: privKey}, &Secp256k1PublicKey{pubKey: &pubKey}, nil
}

// Hash hashes a message
func (e *Secp256k1PrivateKey) Hash(msg []byte, opts HashOpts) ([]byte, error) {
	h, err := e.GetHash(opts)
	if err != nil {
		return nil, err
	}
	return h.Sum(msg), nil
}

// GetHash returns the instance of hash function
func (e *Secp256k1PrivateKey) GetHash(opt HashOpts) (hash.Hash, error) {
	return sha3.NewLegacyKeccak256(), nil
}

// the key's raw byte
func (e *Secp256k1PrivateKey) Bytes() ([]byte, error) {
	return elliptic.Marshal(e.privKey.Curve, e.privKey.X, e.privKey.Y), nil
}

func (secKey *Secp256k1PrivateKey) SaveToPem(file string) error {
	pemFile, err := os.Create(file)
	if err != nil {
		return err
	}

	bytes, _ := x509.MarshalECPrivateKey(secKey.privKey)
	var pemKey = &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: bytes,
	}
	err = pem.Encode(pemFile, pemKey)
	if err != nil {
		return err
	}
	return pemFile.Close()
}

type Secp256k1PublicKey struct {
	pubKey *ecdsa.PublicKey
}

// Algorithm returns the corresponding algorithm
func (s *Secp256k1PublicKey) Algorithm() string {
	return SECP256K1
}

// Sign signs a message's hash
func (s *Secp256k1PublicKey) Sign(k Key, digest []byte) ([]byte, error) {
	return nil, errors.New("cannot sign with Secp256k1 public key")
}

func (s *Secp256k1PublicKey) Encrypt(k Key, plaintext []byte) ([]byte, error) {
	return nil, errors.New("cannot encrypt with Secp256k1 public key")
}

func (s *Secp256k1PublicKey) Decrypt(k Key, ciphertext []byte) ([]byte, error) {
	return nil, errors.New("cannot decrypt with Secp256k1 public key")
}

// Verify verifies a signature
func (s *Secp256k1PublicKey) Verify(k Key, signature []byte, digest []byte) (bool, error) {
	pub := crypto.FromECDSAPub(s.pubKey)
	return crypto.VerifySignature(pub, digest, signature), nil
}

// the key's raw byte
func (e *Secp256k1PublicKey) Bytes() ([]byte, error) {
	return crypto.FromECDSAPub(e.pubKey), nil
}
