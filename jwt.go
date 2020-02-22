package keycloakJWT

type JWTModel struct {
	Audience          string                 `mapstructure:"aud,omitempty"`
	ExpiresAt         int64                  `mapstructure:"exp,omitempty"`
	Id                string                 `mapstructure:"jti,omitempty"`
	IssuedAt          int64                  `mapstructure:"iat,omitempty"`
	Issuer            string                 `mapstructure:"iss,omitempty"`
	NotBefore         int64                  `mapstructure:"nbf,omitempty"`
	Subject           string                 `mapstructure:"sub,omitempty"`
	Scope             string                 `mapstructure:"scope,omitempty"`
	RealmAccess       KeycloakRoles          `mapstructure:"realm_access,omitempty"`
	EmailVerified     bool                   `mapstructure:"email_verified,omitempty"`
	PreferredUsername string                 `mapstructure:"preferred_username,omitempty"`
	GivenName         string                 `mapstructure:"given_name,omitempty"`
	Name              string                 `mapstructure:"name,omitempty"`
	FamilyName        string                 `mapstructure:"family_name,omitempty"`
	Email             string                 `mapstructure:"email,omitempty"`
	ResourceAccess    KeycloakResourceAccess `mapstructure:"resource_access,omitempty"`
}

type KeycloakResourceAccess struct {
	Account KeycloakRoles `mapstructure:"account,omitempty"`
}

type KeycloakRoles struct {
	Roles []string `mapstructure:"roles,omitempty"`
}

type RealmDTO struct {
	PublicKey string `json:"public_key"`
}
