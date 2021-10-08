package models

import (
	"bytes"
	"database/sql"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"time"
)

const challengeExpirationDuration = 30 * time.Minute

var AlgorithmNotSupportedError = errors.New("Provided algorithm is not supported")
var WrongEthAddressFormatError = errors.New("Provided key cannot be ETH address")
var WrongSignatureFormatError = errors.New("Provided signature has wrong format")
var WrongPublicKeyError = errors.New("Provided signature does not match with Key")

// RefreshToken is the database model for refresh tokens.
type AsymmetricKey struct {
	ID        int64     `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	Key       string    `db:"key"`
	Algorithm string    `db:"algorithm"`
	Main      bool      `db:"main"`

	ChallengeToken          uuid.UUID `db:"challenge_token"`
	ChallengeTokenIssuedAt  time.Time `db:"challenge_token_issued_at"`
	ChallengeTokenExpiresAt time.Time `db:"challenge_token_expires_at"`
	ChallengePassed         bool      `db:"challenge_passed"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (AsymmetricKey) TableName() string {
	tableName := "asymmetric_keys"
	return tableName
}

func NewAssymetricKey(userId uuid.UUID, pubkey, algorithm string, main bool) (*AsymmetricKey, error) {
	err := VerifyKeyAndAlgorithm(pubkey, algorithm)
	if err != nil {
		return nil, err
	}

	k := &AsymmetricKey{
		UserID:    userId,
		Key:       pubkey,
		Algorithm: algorithm,
		Main:      main,
	}

	k.generateChallengeToken()
	return k, nil
}

func (a *AsymmetricKey) IsChallengeTokenExpired() bool {
	return time.Now().Unix() >= a.ChallengeTokenExpiresAt.Unix() || a.ChallengePassed
}

func (a *AsymmetricKey) GetChallengeToken(tx *storage.Connection) (uuid.UUID, error) {
	if a.IsChallengeTokenExpired() {
		err := a.generateChallengeToken()
		if err != nil {
			return uuid.Nil, err
		}

		err = tx.UpdateOnly(
			a,
			"challenge_token",
			"challenge_token_issued_at",
			"challenge_token_expires_at",
			"challenge_passed")

		if err != nil {
			return uuid.Nil, err
		}
	}

	return a.ChallengeToken, nil
}

func (a *AsymmetricKey) generateChallengeToken() error {
	newToken, err := uuid.NewV4()
	if err != nil {
		return err
	}

	a.ChallengeToken = newToken
	a.ChallengeTokenIssuedAt = time.Now()
	a.ChallengeTokenExpiresAt = time.Now().Add(challengeExpirationDuration)
	a.ChallengePassed = false

	return nil
}

func (a *AsymmetricKey) VerifySignature(signature string) error {
	var err error
	switch a.Algorithm {
	case "ETH":
		err = a.verifyEthKeySignature(signature)
	default:
		return AlgorithmNotSupportedError
	}

	if err == nil {
		a.ChallengePassed = true
	}
	return err
}

func (a *AsymmetricKey) verifyEthKeySignature(rawSignature string) error {
	log := logrus.WithField("component", "signatureVerification")
	log.Infof("Signature: %v", rawSignature)
	log.Infof("Challenge token: %v", a.ChallengeToken.String())

	log.Infof("Equal tokens strings: %v", a.ChallengeToken.String() == "c2918781-fa53-44b1-8a0f-7da323e6fcec")
	log.Infof("Equal tokens bytes: %v", bytes.Equal([]byte(a.ChallengeToken.String()), []byte("c2918781-fa53-44b1-8a0f-7da323e6fcec")))
	signature, err := hexutil.Decode(rawSignature)
	if err != nil {
		return err
	}
	log.Infof("Equal signatures: %v", rawSignature == "0x84be2bca9f4ab3ffa5158f0ab857987ad5e286a4b32f98c22c6d74659cff9726777ca74f7469c03b08301cbe3a1c381ece2c57249cfc6e4a0584dcff4b28d73b1c")

	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	if signature[64] != 27 && signature[64] != 28 {
		return WrongSignatureFormatError
	}
	signature[64] -= 27

	signaturePublicKey, err := crypto.SigToPub(signEthMessageHash([]byte(a.ChallengeToken.String())), signature)
	if err != nil {
		return err
	}

	addr := crypto.PubkeyToAddress(*signaturePublicKey)
	log.Infof("Address: %s", addr.String())
	if addr.String() != a.Key {
		return WrongPublicKeyError
	}

	return nil
}

// verifyKeyAndAlgorithm verifies public key format for specific algorithm.
// If key satisfies conditions, nil error is returned
func VerifyKeyAndAlgorithm(pubkey, algorithm string) error {
	var err error
	switch algorithm {
	case "ETH":
		err = verifyEthKey(pubkey)
	default:
		return AlgorithmNotSupportedError
	}
	return err
}

func verifyEthKey(key string) error {
	if common.IsHexAddress(key) {
		return nil
	}
	return WrongEthAddressFormatError
}

func signEthMessageHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

func FindMainAsymmetricKeyByUser(tx *storage.Connection, user *User) (*AsymmetricKey, error) {
	key := &AsymmetricKey{}
	if err := tx.Q().Where("user_id = ? and main = true", user.ID).First(key); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return &AsymmetricKey{}, nil
		}
		return &AsymmetricKey{}, errors.Wrap(err, "error finding keys")
	}
	return key, nil
}
