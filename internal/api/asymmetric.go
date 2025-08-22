package api

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
)

type AsymmetricSignupResponse struct {
	ChallengeToken string `json:"challenge_token"`
}

type AsymmetricTokenStorage struct {
	mu     sync.RWMutex
	tokens map[string]string
}

func NewAsymmetricTokenStorage() *AsymmetricTokenStorage {
	return &AsymmetricTokenStorage{
		tokens: make(map[string]string),
	}
}

// For now supports only EVM-style addresses
func (a *API) validateAsymmetricAddress(address string) (string, error) {
	re := regexp.MustCompile("^0x[0-9a-fA-F]{40}$")
	if !re.MatchString(address) {
		return "", apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Asymmetric address must be a valid Ethereum address")
	}

	return address, nil
}

func (a *API) validateAsymmetricSignature(signature string) (string, error) {
	re := regexp.MustCompile("^0x[0-9a-fA-F]{130}$")
	if !re.MatchString(signature) {
		return "", apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Asymmetric signature must be a valid Ethereum signature")
	}

	return signature, nil
}

func (a *API) generateAsymmetricToken() (string, error) {
	token := uuid.New().String()
	return token, nil
}

// TODO: fix potential memleak here, unverified tokens will never be deleted
func (a *API) setAsymmetricAddressForToken(challengeToken, address string) {
	a.ats.mu.Lock()
	defer a.ats.mu.Unlock()
	a.ats.tokens[challengeToken] = address
}

func (a *API) getAsymmetricAddressForToken(challengeToken string) (string, bool) {
	a.ats.mu.RLock()
	defer a.ats.mu.RUnlock()
	address, ok := a.ats.tokens[challengeToken]

	return address, ok
}

func (a *API) deleteAsymmetricAddressForToken(challengeToken string) {
	a.ats.mu.Lock()
	defer a.ats.mu.Unlock()
	delete(a.ats.tokens, challengeToken)
}

func recoverAsymmetricAddress(message []byte, sig []byte) (string, error) {
	if len(sig) != 65 {
		return "", fmt.Errorf("invalid signature length: got %d, want 65", len(sig))
	}

	if sig[64] >= 27 {
		sig[64] -= 27
	}

	msg := computeEthereumSignedMessageHash(message)

	pubkey, err := crypto.SigToPub(msg, sig)
	if err != nil {
		return "", fmt.Errorf("signature recovery failed: %w", err)
	}

	addr := crypto.PubkeyToAddress(*pubkey)
	return addr.Hex(), nil
}

// computeEthereumSignedMessageHash accepts an arbitrary message, prepends a known message,
// and hashes the result using keccak256. The known message added to the input before hashing is
// "\x19Ethereum Signed Message:\n" + len(message).
func computeEthereumSignedMessageHash(message []byte) []byte {
	return crypto.Keccak256(
		[]byte(
			fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), string(message)),
		),
	)
}
