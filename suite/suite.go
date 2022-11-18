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
	"crypto"
	"hash"
)

type Key interface {
}

type PrivateKey interface {
	//Bytes bit representation of the key
	Bytes() ([]byte, error)
	//Algorithm returns the corresponding algorithm
	Algorithm() string
	PublicKey() (PublicKey, error)
	Signer
	Verifier
	Encrypter
	Decrypter
}

type PublicKey interface {
	//Bytes bit representation of the key
	Bytes() ([]byte, error)
	//Algorithm returns the corresponding algorithm
	Algorithm() string
	Signer
	Verifier
	Encrypter
	Decrypter
}

type SymmetricKey interface {
	//Bytes bit representation of the key
	Bytes() ([]byte, error)
	//Algorithm returns the corresponding algorithm
	Algorithm() string

	Encrypter
	Decrypter
}

type AsymmetricKeyPair interface {
	GetKeyPair() (PrivateKey, PublicKey, error)
	Algorithm() string
}

type Hasher interface {
	hash.Hash
}

// Key generation options for CryptoProvider
type KeyGenOpts interface {
	Algorithm() string
}

// HashOpts contains hash options for CryptoProvider
type HashOpts interface {
	Algorithm() string
}

// EncrypterOpts contains encrypting options
type EncrypterOpts interface {
}

// DecrypterOpts contains decrypting options
type DecrypterOpts interface {
}

// SignerOpts contain signing options
type SignerOpts interface {
	crypto.SignerOpts
}

type Signer interface {
	//Sign signs a message's hash
	Sign(k Key, digest []byte) ([]byte, error)
}

type Verifier interface {
	Verify(k Key, signature, digest []byte) (bool, error)
}

type Encrypter interface {
	Encrypt(k Key, plaintext []byte) ([]byte, error)
}

type Decrypter interface {
	Decrypt(k Key, ciphertext []byte) ([]byte, error)
}

// bytehub+ crytograhic provider
type CryptoSuiteProvider interface {
	//KeyGen generates a new symmetric key
	KeyGen(opts KeyGenOpts) (Key, error)

	//KeyGen generates a new pair of asymmetric key
	KeyPairGen(opts KeyGenOpts) (Key, Key, error)

	//Hash hashes a message
	Hash(msg []byte, opts HashOpts) ([]byte, error)

	//GetHash returns the instance of hash function
	GetHash(opt HashOpts) (hash.Hash, error)

	Encrypter
	Decrypter
	Signer
	Verifier
}
