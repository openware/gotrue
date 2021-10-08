package api

import (
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/models"
	"net/http"

	"github.com/netlify/gotrue/storage"
)

//signature 0xbd814e4f92afd63be08893be8bf7f88c0566ad6991eb9a1e81d81bbc8173233615ff9705fda470bb23b72a1c308768ebf61fc245a8e955417b201ac56d9243dc1c
// recoveredPubkey 0x048fe530980a230c6c9077418e80ac0119eae6e8b0f4157b9974337c983c685bc25af19f423ddaf7229d714bbb09848dc276bcab8c3ef34fdf8276da2ff8946135
// recoveredAddress 0x6BE46d7D863666546b77951D5dfffcF075F36E68

//signature 0x84be2bca9f4ab3ffa5158f0ab857987ad5e286a4b32f98c22c6d74659cff9726777ca74f7469c03b08301cbe3a1c381ece2c57249cfc6e4a0584dcff4b28d73b1c
// recoveredPubkey 0x048fe530980a230c6c9077418e80ac0119eae6e8b0f4157b9974337c983c685bc25af19f423ddaf7229d714bbb09848dc276bcab8c3ef34fdf8276da2ff8946135
// recoveredAddress 0x6BE46d7D863666546b77951D5dfffcF075F36E68

// GetChallengeTokenParams are the parameters the Signup endpoint accepts
type GetChallengeTokenParams struct {
	Key       string `json:"key"`
	Algorithm string `json:"algorithm"`
}

// GetChallengeTokenParams are the parameters the Signup endpoint accepts
type GetChallengeTokenResponse struct {
	ChallengeToken string `json:"challenge_token"`
}

func (a *API) GetChallengeToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)

	params := &GetChallengeTokenParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read GetChallengeTokenParams params: %v", err)
	}

	err = models.VerifyKeyAndAlgorithm(params.Key, params.Algorithm)
	if err != nil {
		return unprocessableEntityError("Key verification failed: %v", err)
	}

	user, key, err := models.FindUserWithAsymmetrickey(a.db, params.Key)
	var challengeToken uuid.UUID

	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if user != nil && key != nil {
			challengeToken, terr = key.GetChallengeToken(tx)
			if terr != nil {
				return terr
			}
		} else if user == nil && key == nil {
			if config.DisableSignup {
				return forbiddenError("Signups not allowed for this instance")
			}

			user, terr = a.signupNewUser(ctx, tx, &SignupParams{
				Email:    "",
				Phone:    "",
				Password: "",
				Data:     nil,
				Provider: "AsymmetricKey",
			})
			if terr != nil {
				return terr
			}

			key, terr = models.NewAssymetricKey(user.ID, params.Key, params.Algorithm, true)
			if terr != nil {
				return terr
			}

			if terr := tx.Create(key); terr != nil {
				return terr
			}

			challengeToken, terr = key.GetChallengeToken(tx)
			if terr != nil {
				return terr
			}
		} else {
			return internalServerError("Impossible case")
		}
		return nil
	})

	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, GetChallengeTokenResponse{ChallengeToken: challengeToken.String()})
}

// AsymmetricSignInParams are the parameters the Signin endpoint accepts
type AsymmetricSignInParams struct {
	Key                     string `json:"key"`
	ChallengeTokenSignature string `json:"challenge_token_signature"`
}

type AsymmetricSignInResponse struct {
	Passed bool `json:"true"`
}

func (a *API) SignInWithAsymmetricKey(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	cookie := r.Header.Get(useCookieHeader)

	params := &AsymmetricSignInParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read AsymmetricSignInParams params: %v", err)
	}

	user, key, err := models.FindUserWithAsymmetrickey(a.db, params.Key)
	if err != nil && models.IsNotFoundError(err) {
		return unauthorizedError("Unauthorized")
	}
	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding key").WithInternalError(err)
	}

	if key.IsChallengeTokenExpired() {
		return unprocessableEntityError("Key challenge token has been expired")
	}

	if err = key.VerifySignature(params.ChallengeTokenSignature); err != nil {
		return unprocessableEntityError("Signature verification failed:%v", err)
	}

	var token *AccessTokenResponse
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		terr = tx.UpdateOnly(key, "challenge_passed")
		if terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(ctx, tx, user)
		if terr != nil {
			return terr
		}

		if cookie != "" && config.Cookie.Duration > 0 {
			if terr = a.setCookieToken(config, token.Token, cookie == useSessionCookie, w); terr != nil {
				return internalServerError("Failed to set JWT cookie. %s", terr)
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	token.User = user
	return sendJSON(w, http.StatusOK, token)
}
