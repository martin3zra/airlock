package airlock

type config struct {
	tokenExpireIn int64
	signKey       []byte
	storeInCookie bool
}

func NewConfig(storeInCookie bool, expireIn int64, encryptionKey string) config {
	return config{
		tokenExpireIn: expireIn,
		signKey:       []byte(encryptionKey),
		storeInCookie: storeInCookie,
	}
}
