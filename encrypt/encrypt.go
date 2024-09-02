package encrypt

import "io"

type Encrypter interface {
	Encrypt(encrypted io.Reader, data io.Writer) error
	Decrypt(encrypted io.Reader) ([]byte, error)
}
