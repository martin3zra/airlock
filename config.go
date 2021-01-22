package airlock

// Config type that expose all the requirements that AirLock needs
// in order to issue token and performs others operations
type Config struct {
	tokenExpireIn  int64
	signKey        []byte
	storeInCookie  bool
	redirectTo     string
	redirectBackTo string
}

// NewConfig return a new instance of type config
// accept if the user wants store the token
// as cookie, the token expiration time
// and the encryption key and the
// redirection path
func NewConfig(storeInCookie bool, expireIn int64, encryptionKey string, redirectTo *string, redirectBackTo *string) Config {

	var defaultPathToRedirect = "home"
	if redirectTo != nil {
		defaultPathToRedirect = *redirectTo
	}

	var defaultPathToRedirectBackTo = "/auth/login"
	if redirectBackTo != nil {
		defaultPathToRedirectBackTo = *redirectBackTo
	}

	return Config{
		tokenExpireIn:  expireIn,
		signKey:        []byte(encryptionKey),
		storeInCookie:  storeInCookie,
		redirectTo:     defaultPathToRedirect,
		redirectBackTo: defaultPathToRedirectBackTo,
	}
}
