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

// implementation of ethereum sign, verify, hash, RSA asymmetric and AES symmetric algorithm
package suite

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash"
	"io/ioutil"

	ethCrypto "github.com/ethereum/go-ethereum/crypto"
)

type EthCryptoSuite struct {
	SignKey      Secp256k1PrivateKey
	VerifyKey    Secp256k1PublicKey
	SymmetricKey AESKey
	RSAKey       RSAPrivateKey
}

// Sign signs a message's hash
func (e *EthCryptoSuite) Sign(k Key, digest []byte) ([]byte, error) {
	return e.SignKey.Sign(
		k, digest)
}

// Decrypt decrypts msg. The opts argument should be appropriate for
// the primitive used. See the documentation in each implementation for
// details.
func (e *EthCryptoSuite) Decrypt(k Key, ciphertext []byte) ([]byte, error) {
	return e.SymmetricKey.Decrypt(k, ciphertext)
}

// GenSymmetricKey generates a new symmetric key
func (e *EthCryptoSuite) GenSymmetricKey(opts KeyGenOpts) (Key, error) {
	return nil, errors.New("Key has to be specified by user")
}

// KeyGen generates a new pair of asymmetric key
func (e *EthCryptoSuite) GenAsymmetricKey(opts KeyGenOpts) (Key, Key, error) {
	if opts.Algorithm() == SECP256K1 {
		return GenSignKeyPair()
	} else {
		return nil, nil, errors.New("Algorithm doesn't support")
	}
}

// Hash hashes a message
func (e *EthCryptoSuite) Hash(msg []byte, opts HashOpts) ([]byte, error) {
	return ethCrypto.Keccak256(msg), nil
}

// GetHash returns the instance of hash function
func (e *EthCryptoSuite) GetHash(opt HashOpts) (hash.Hash, error) {
	return ethCrypto.NewKeccakState(), nil
}

func (e *EthCryptoSuite) Encrypt(k Key, plaintext []byte) ([]byte, error) {
	return e.SymmetricKey.Encrypt(k, plaintext)
}

// Verify verifies a signature
func (e *EthCryptoSuite) Verify(k Key, signature []byte, digest []byte) (bool, error) {
	return e.VerifyKey.Verify(k, signature, digest)
}

func (ecs *EthCryptoSuite) LoadPrivateKeyFromPEM(file string, password string) error {
	if file == "" {
		return errors.New("PEM file is required")
	}
	privFile, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	privPem, _ := pem.Decode(privFile)
	var privKey []byte
	if privPem.Type != "EC PRIVATE KEY" {
		return errors.New("invalid key format")
	}

	if password != "" {
		privKey, _ = x509.DecryptPEMBlock(privPem, []byte(password))
	} else {
		privKey = privPem.Bytes
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privKey); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privKey); err != nil {
			return errors.New("parse private key failed")
		}
	}

	var secp256k1PriKey *Secp256k1PrivateKey
	secp256k1PriKey, ok := parsedKey.(*Secp256k1PrivateKey)
	if !ok {
		return errors.New("Unable to parse seck256k1 private key")
	}
	ecs.SignKey = *secp256k1PriKey
	return nil
}

func (ecs *EthCryptoSuite) LoadRSAPrivateKeyFromPEM(file string, password string) error {
	if file == "" {
		return errors.New("PEM file is required")
	}
	privFile, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	privPem, _ := pem.Decode(privFile)
	var privKey []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		return errors.New("invalid key format")
	}

	if password != "" {
		privKey, _ = x509.DecryptPEMBlock(privPem, []byte(password))
	} else {
		privKey = privPem.Bytes
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privKey); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privKey); err != nil {
			return errors.New("parse RSA private key failed")
		}
	}

	var rsaPrivKey *rsa.PrivateKey
	rsaPrivKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return errors.New("Unable to parse RSA private key")
	}
	ecs.RSAKey = RSAPrivateKey{PrivKey: rsaPrivKey}
	return nil
}

func (ecs *EthCryptoSuite) SetSymmeticKey(key []byte) error {
	l := len(key)
	if l == 12 || l == 16 || l == 32 {
		ecs.SymmetricKey = AESKey{bytes: key}
	} else {
		return errors.New("AES key len must be 12, 16 or 32")
	}
	return nil
}
