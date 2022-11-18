package suite

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

type RSAPrivateKey struct {
	PrivKey *rsa.PrivateKey
	PubKey  RSAPublicKey
}

func (r *RSAPrivateKey) PublicKey() (PublicKey, error) {
	return &r.PubKey, nil
}

// Sign signs a message's hash
func (r *RSAPrivateKey) Sign(k Key, digest []byte) ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

func (r *RSAPrivateKey) Verify(k Key, signature []byte, digest []byte) (bool, error) {
	panic("not implemented") // TODO: Implement
}

func (r *RSAPrivateKey) Encrypt(k Key, plaintext []byte) ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

func (r *RSAPrivateKey) Decrypt(k Key, ciphertext []byte) ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

func (r *RSAPrivateKey) GetKeyPair() (PrivateKey, PublicKey, error) {
	return r, &r.PubKey, nil
}

func (r *RSAPrivateKey) Algorithm() string {
	panic("not implemented") // TODO: Implement
}

func (r *RSAPrivateKey) String() string {
	b, _ := r.Bytes()
	return fmt.Sprintf("%x", b)
}

// the key's raw byte
func (k *RSAPrivateKey) Bytes() ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(k.PrivKey), nil
}

// PrivateKey returns true is this is a asymmetric private key or symmetric security key
func (r *RSAPrivateKey) PrivateKey() bool {
	return true
}

// symmetric returns true if this key is symmetric, otherwise false
func (r *RSAPrivateKey) Symmetric() bool {
	return false
}

type RSAPublicKey struct {
	pubKey *rsa.PublicKey
}

// Algorithm returns the corresponding algorithm
func (r *RSAPublicKey) Algorithm() string {
	panic("not implemented") // TODO: Implement
}

// Sign signs a message's hash
func (r *RSAPublicKey) Sign(k Key, digest []byte) ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

func (r *RSAPublicKey) Verify(k Key, signature []byte, digest []byte) (bool, error) {
	panic("not implemented") // TODO: Implement
}

func (r *RSAPublicKey) Encrypt(k Key, plaintext []byte) ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

func (r *RSAPublicKey) Decrypt(k Key, ciphertext []byte) ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

// the key's raw byte
func (k *RSAPublicKey) Bytes() ([]byte, error) {
	return x509.MarshalPKCS1PublicKey(k.pubKey), nil
}

// PrivateKey returns true is this is a asymmetric private key or symmetric security key
func (r *RSAPublicKey) PrivateKey() bool {
	return false
}

// symmetric returns true if this key is symmetric, otherwise false
func (r *RSAPublicKey) Symmetric() bool {
	return false
}

// if this is a asymmetric key, returns the corresponding Public key, otherwise error
func (r *RSAPublicKey) PublicKey() (PublicKey, error) {
	return r, nil
}

func NewRSAPrivateKey() (Key, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pubKey := RSAPublicKey{pubKey: &privKey.PublicKey}
	return &RSAPrivateKey{PrivKey: privKey, PubKey: pubKey}, nil
}
