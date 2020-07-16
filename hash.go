package airlock

import "golang.org/x/crypto/bcrypt"

type hash struct{}

func newHashable() hash {
	return hash{}
}
func (hash) Make(value string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(value), 14)
	if err != nil {
		panic(err.Error())
	}

	return string(bytes)
}

func (hash) Check(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
