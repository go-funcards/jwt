package jwt

import (
	"crypto/rsa"
	"errors"
	"github.com/cristalhq/jwt/v4"
	"time"
)

var (
	ErrNoPrivKeyFile  = errors.New("private key file unreadable")
	ErrInvalidPrivKey = errors.New("RSA private key invalid")
)

var _ Generator = (*generator)(nil)

type SignerConfig struct {
	PrivateKey string        `yaml:"private_key" env:"PRIVATE_KEY" env-required:"true"`
	Audience   []string      `yaml:"audience" env:"AUDIENCE" env-required:"true"`
	Algorithm  jwt.Algorithm `yaml:"algorithm" env:"ALGORITHM" env-default:"RS256"`
	TTL        time.Duration `yaml:"ttl" env:"TTL" env-default:"5m"`
}

type Generator interface {
	GenerateToken(user User) (string, error)
}

type generator struct {
	cfg *SignerConfig
	b   *jwt.Builder
}

func (cfg *SignerConfig) privateKey() (*rsa.PrivateKey, error) {
	prv, err := GetKey(cfg.PrivateKey)
	if err != nil {
		return nil, ErrNoPrivKeyFile
	}
	prvKey, err := ParseRSAPrivateKeyFromPEM(prv)
	if err != nil {
		return nil, ErrInvalidPrivKey
	}
	return prvKey, nil
}

func (cfg *SignerConfig) NewGenerator(privKey *rsa.PrivateKey) (*generator, error) {
	signer, err := jwt.NewSignerRS(cfg.Algorithm, privKey)
	if err != nil {
		return nil, err
	}
	return &generator{cfg: cfg, b: jwt.NewBuilder(signer)}, nil
}

func (cfg *SignerConfig) Generator() (*generator, error) {
	privKey, err := cfg.privateKey()
	if err != nil {
		return nil, err
	}
	return cfg.NewGenerator(privKey)
}

func (b *generator) GenerateToken(user User) (string, error) {
	claims := UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        user.UserID,
			Audience:  b.cfg.Audience,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(b.cfg.TTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		Name:  user.Name,
		Email: user.Email,
		Roles: user.Roles,
	}

	token, err := b.b.Build(claims)
	if err != nil {
		return "", err
	}

	return token.String(), nil
}
