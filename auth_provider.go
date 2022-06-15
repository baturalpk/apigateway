package apigateway

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/oklog/ulid/v2"
)

func NewAuthProvider(conf Config) (*authProvider, error) {
	scf := conf.Authentication.IdentityStore
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
		scf.User, scf.Password, scf.DBName, scf.DBName, scf.Port)

	gdb, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	t := time.Unix(1000000, 0)
	entropy := ulid.Monotonic(rand.New(rand.NewSource(t.UnixNano())), 0)

	return &authProvider{
		config:        conf,
		identityDB:    gdb,
		ulidTimestamp: ulid.Timestamp(t),
		ulidEntropy:   entropy,
	}, nil
}

type authProvider struct {
	config        Config
	identityDB    *gorm.DB
	ulidTimestamp uint64
	ulidEntropy   *ulid.MonotonicEntropy
}

// Identity entity
type Identity struct {
	ID       string `gorm:"primaryKey;autoIncrement:false"`
	Email    string `gorm:"uniqueIndex"`
	Password string
}

// --- DTOs ---

type NewIdentityRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type NewIdentityResponse struct {
	existingEmailError bool
}

type AuthenticateRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type AuthenticateResponse struct {
	tokenString                string
	identityVerificationFailed bool
}

type ValidateAuthorizationResponse struct {
	id string
}

func (ap *authProvider) NewIdentity(req NewIdentityRequest) (NewIdentityResponse, error) {
	var identity Identity
	preTx := ap.identityDB.Where("email = ?", req.Email).First(&identity)
	if preTx.Error == nil {
		return NewIdentityResponse{existingEmailError: true}, errors.New("existing email or unknown error")
	}

	id, err := ap.newUniqueID()
	if err != nil {
		return NewIdentityResponse{}, err
	}
	hashPass, err := bcrypt.GenerateFromPassword([]byte(req.Password), 16)
	if err != nil {
		return NewIdentityResponse{}, err
	}
	tx := ap.identityDB.Create(&Identity{
		ID:       id,
		Email:    req.Email,
		Password: string(hashPass),
	})
	if err := tx.Error; err != nil {
		return NewIdentityResponse{}, err
	}
	return NewIdentityResponse{}, nil
}

func (ap *authProvider) Authenticate(req AuthenticateRequest) (AuthenticateResponse, error) {
	// Fetch identity
	var identity Identity
	tx := ap.identityDB.
		Where("email = ?", req.Email).
		First(&identity)

	if err := tx.Error; err != nil {
		return AuthenticateResponse{}, err
	}

	// Validate password
	if err := bcrypt.CompareHashAndPassword([]byte(identity.Password), []byte(req.Password)); err != nil {
		return AuthenticateResponse{identityVerificationFailed: true}, err
	}

	// Generate new access token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": identity.ID,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
		"iat": time.Now(),
	})

	tokenString, err := token.SignedString(ap.config.Authorization.HmacSecret)
	if err != nil {
		return AuthenticateResponse{}, err
	}

	return AuthenticateResponse{tokenString: tokenString}, nil
}

func (ap *authProvider) ValidateAuthorization(tokenString string) (ValidateAuthorizationResponse, error) {
	// Parse and verify token string
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(ap.config.Authorization.HmacSecret), nil
	})
	if err != nil {
		return ValidateAuthorizationResponse{}, err
	}

	// Unpack the claims - if success...
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return ValidateAuthorizationResponse{id: claims["sub"].(string)}, nil
	}

	// ...else - always fails
	return ValidateAuthorizationResponse{}, errors.New("invalid access token")
}

func (ap *authProvider) newUniqueID() (string, error) {
	id, err := ulid.New(ap.ulidTimestamp, ap.ulidEntropy)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
