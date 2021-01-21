package airlock

// Config type that expose all the requirements that AirLock needs
// in order to issue token and performs others operations
type Config struct {
	tokenExpireIn int64
	signKey       []byte
	storeInCookie bool
	redirectTo    string
}

// NewConfig return a new instance of type config
// accept if the user wants store the token
// as cookie, the token expiration time
// and the encryption key and the
// redirection path
func NewConfig(storeInCookie bool, expireIn int64, encryptionKey string, redirectTo *string) Config {

	var defaultPathToRedirect = "home"
	if redirectTo != nil {
		defaultPathToRedirect = *redirectTo
	}

	return Config{
		tokenExpireIn: expireIn,
		signKey:       []byte(encryptionKey),
		storeInCookie: storeInCookie,
		redirectTo:    defaultPathToRedirect,
	}
}
