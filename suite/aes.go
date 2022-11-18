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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AESKey struct {
	bytes []byte
	nonce []byte
}

// Algorithm returns the corresponding algorithm
func (a *AESKey) Algorithm() string {
	return AES
}

func (a *AESKey) Decrypt(k Key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.(*AESKey).bytes)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, a.nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (a *AESKey) Encrypt(k Key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.(*AESKey).bytes)
	if err != nil {
		return nil, err
	}

	a.nonce = make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, a.nonce); err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, a.nonce, plaintext, nil)
	return ciphertext, nil
}

// the key's raw byte
func (a *AESKey) Bytes() ([]byte, error) {
	return a.bytes, nil
}
