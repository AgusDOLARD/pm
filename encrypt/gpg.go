package encrypt

import (
	"fmt"
	"io"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

const pgp_encoding = crypto.Bytes

type GpgEncrypter struct {
	publicKey  *crypto.Key
	privateKey *crypto.Key
}

func NewEncrypter(name, email string) (*GpgEncrypter, error) {
	pgp := crypto.PGPWithProfile(profile.RFC4880())
	genHandler, err := pgp.KeyGeneration().
		AddUserId(name, email).
		New().
		GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("error generating key: %v", err)
	}

	pubKey, err := genHandler.ToPublic()
	if err != nil {
		return nil, fmt.Errorf("error converting key to public: %v", err)
	}

	return &GpgEncrypter{
		publicKey:  pubKey,
		privateKey: genHandler,
	}, nil
}

func NewEncrypterFromReader(privKeyReader io.Reader) (*GpgEncrypter, error) {
	privKey, err := crypto.NewKeyFromReader(privKeyReader)
	if err != nil {
		return nil, fmt.Errorf("error creating key: %v", err)
	}

	if !privKey.IsPrivate() {
		return nil, fmt.Errorf("key is not private: %v", err)
	}

	pubKey, err := privKey.ToPublic()
	if err != nil {
		return nil, fmt.Errorf("error converting key to public: %v", err)
	}

	return &GpgEncrypter{
		publicKey:  pubKey,
		privateKey: privKey,
	}, nil
}

func (e *GpgEncrypter) WriteTo(w io.Writer) (int64, error) {
	pk, err := e.privateKey.Serialize()
	if err != nil {
		return 0, fmt.Errorf("error serializing key: %v", err)
	}

	n, err := w.Write(pk)
	if err != nil {
		return int64(n), fmt.Errorf("error writing private key to writer: %v", err)
	}

	return int64(n), nil
}

func (e *GpgEncrypter) Encrypt(encrypted io.Writer, data io.Reader) error {
	pgp := crypto.PGP()
	encryptedHandler, err := pgp.Encryption().
		Recipient(e.publicKey).
		New()
	if err != nil {
		return fmt.Errorf("error creating encryption handler: %v", err)
	}

	enc, err := encryptedHandler.EncryptingWriter(encrypted, pgp_encoding)
	if err != nil {
		return fmt.Errorf("error creating encrypting writer: %v", err)
	}

	_, err = io.Copy(enc, data)
	if err != nil {
		return fmt.Errorf("error encrypting data: %v", err)
	}

	return enc.Close()
}

func (e *GpgEncrypter) Decrypt(encrypted io.Reader) ([]byte, error) {
	pgp := crypto.PGP()
	decryptHandler, err := pgp.Decryption().
		DecryptionKey(e.privateKey).
		New()
	if err != nil {
		return nil, fmt.Errorf("error creating decryption handler: %v", err)
	}

	encrypedData, err := decryptHandler.DecryptingReader(encrypted, pgp_encoding)
	if err != nil {
		return nil, fmt.Errorf("error creating decrypting reader: %v", err)
	}

	return encrypedData.ReadAll()
}

func (e *GpgEncrypter) ClearPrivateParams() bool {
	return e.privateKey.ClearPrivateParams()
}
