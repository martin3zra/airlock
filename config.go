package airlock

type config struct {
	tokenExpireIn int64  `json:"token_expire_in"`
	signKey       []byte `json:"sign_key"`
}

func NewConfig(expireIn int64, encryptionKey string) config {
	return config{
		tokenExpireIn: expireIn,
		signKey:       []byte(encryptionKey),
	}
}
