package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"github.com/cristalhq/jwt/v4"
)

var (
	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")
	ErrTokenInvalidClaims      = errors.New("token has invalid claims")
	ErrNoPubKeyFile            = errors.New("public key file unreadable")
	ErrInvalidPubKey           = errors.New("RSA public key invalid")
)

var _ Verifier = (*verifier)(nil)

type VerifierConfig struct {
	PublicKey string        `mapstructure:"public_key" yaml:"public_key" env:"PUBLIC_KEY" env-required:"true"`
	Audience  string        `mapstructure:"audience" yaml:"audience" env:"AUDIENCE" env-required:"true"`
	Algorithm jwt.Algorithm `mapstructure:"algorithm" yaml:"algorithm" env:"ALGORITHM" env-default:"RS256"`
}

type Verifier interface {
	Parse(token string) (*jwt.Token, UserClaims, error)
	ExtractUser(token string) (User, error)
}

type verifier struct {
	cfg *VerifierConfig
	v   jwt.Verifier
}

func (cfg *VerifierConfig) publicKey() (*rsa.PublicKey, error) {
	pub, err := GetKey(cfg.PublicKey)
	if err != nil {
		return nil, ErrNoPubKeyFile
	}
	pubKey, err := ParseRSAPublicKeyFromPEM(pub)
	if err != nil {
		return nil, ErrInvalidPubKey
	}
	return pubKey, nil
}

func (cfg *VerifierConfig) NewVerifier(pubKey *rsa.PublicKey) (*verifier, error) {
	v, err := jwt.NewVerifierRS(cfg.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	return &verifier{cfg: cfg, v: v}, nil
}

func (cfg *VerifierConfig) Verifier() (*verifier, error) {
	pubKey, err := cfg.publicKey()
	if err != nil {
		return nil, err
	}
	return cfg.NewVerifier(pubKey)
}

func (v *verifier) Parse(token string) (*jwt.Token, UserClaims, error) {
	var uc UserClaims
	t, err := jwt.Parse([]byte(token), v.v)
	if err != nil {
		return nil, uc, ErrInvalidSigningAlgorithm
	}
	uc, err = Unmarshal(t.Claims())
	if err == nil {
		err = uc.Validate(v.cfg.Audience)
	}
	return t, uc, err
}

func (v *verifier) ExtractUser(token string) (User, error) {
	_, uc, err := v.Parse(token)
	if err != nil {
		return User{}, err
	}
	return uc.User(), nil
}

func Unmarshal(claims json.RawMessage) (UserClaims, error) {
	var uc UserClaims
	if err := json.Unmarshal(claims, &uc); err != nil {
		return uc, ErrTokenInvalidClaims
	}
	return uc, nil
}
