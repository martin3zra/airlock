# AirLock

```shell script
go get github.com/martin3zra/airlock
```
## SQL DDL

Run this sql ddl
```sql
CREATE TABLE `oauth_access_tokens` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `token` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `revoked` tinyint(1) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `expires_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `oauth_access_tokens_user_id_index` (`user_id`),
  KEY `revoked_index` (`revoked`),
  KEY `token_index` (`token`(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `oauth_refresh_tokens` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `refresh_token` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `revoked` tinyint(1) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `expires_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `oauth_access_tokens_user_id_index` (`user_id`),
  KEY `revoked_index` (`revoked`),
  KEY `refresh_token_index` (`refresh_token`(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

```

## Configuration

The expire time is the number of minutes that the access token should be considered valid. This security feature keeps tokens short-lived so they have less time to be guessed. You may change this as needed.

The encryption keys AirLock needs in order to generate access token. The generated keys are not typically kept in source control:

```go
package main
import (
    "database/sql"
    "github.com/gorilla/mux"
    "github.com/martin3zra/airlock"
    "github.com/martin3zra/router"
)

func main() {
    expireIn := int64(124000)
    encryptionKey := "---PRIVATE KEY ---"
    // optional redirect path
    var redirectTo *string
    var redirectBackTo *string

    // Create a new configuration instance
    config := airlock.NewConfig(expireIn, encryptionKey, redirectTo, redirectBackTo)
    route := router.NewRoute(mux.NewRouter())
    var db *sql.DB

    airLock := airlock.NewAirLock(config, route, db)
    airLock.Routes()
}
```
