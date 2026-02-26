package oauth

type Store interface {
	GetClient
	GetRedirectURI
	CreateAuthorizationCode
	GetAuthorizationCode
	MarkAuthorizationCodeUsed
}

type TokenSigner interface {
	SignAccessToken
}

type Service struct {
	store  Store
	signer TokenSigner
	issuer string
}
