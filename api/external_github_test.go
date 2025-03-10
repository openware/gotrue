package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/netlify/gotrue/models"
	"github.com/stretchr/testify/require"
)

func (ts *ExternalTestSuite) TestSignupExternalGithub() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=github", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Github.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Github.ClientID, q.Get("client_id"))
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("user:email", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return ts.Config.JWT.GetVerificationKey(), nil
	})
	ts.Require().NoError(err)

	ts.Equal("github", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func GitHubTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, emails string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Github.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"github_token","expires_in":100000}`)
		case "/api/v3/user":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":123, "name":"GitHub Test","avatar_url":"http://example.com/avatar"}`)
		case "/api/v3/user/emails":
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, emails)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown github oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Github.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalGitHub_AuthorizationCode() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"github@example.com", "primary": true, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "github", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "github@example.com", "GitHub Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalGitHubDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"github@example.com", "primary": true, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "github", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "github@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalGitHubDisableSignupErrorWhenEmptyEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"primary": true, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "github", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "github@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalGitHubDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("123", "github@example.com", "GitHub Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"github@example.com", "primary": true, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "github", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "github@example.com", "GitHub Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalGitHubDisableSignupSuccessWithNonPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("123", "secondary@example.com", "GitHub Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"primary@example.com", "primary": true, "verified": true},{"email":"secondary@example.com", "primary": false, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "github", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "secondary@example.com", "GitHub Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGitHubSuccessWhenMatchingToken() {
	// name and avatar should be populated from GitHub API
	ts.createUser("123", "github@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"github@example.com", "primary": true, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "github", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "github@example.com", "GitHub Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGitHubErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"github@example.com", "primary": true, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	w := performAuthorizationRequest(ts, "github", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGitHubErrorWhenWrongToken() {
	ts.createUser("123", "github@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"github@example.com", "primary": true, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	w := performAuthorizationRequest(ts, "github", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGitHubErrorWhenEmailDoesntMatch() {
	ts.createUser("123", "github@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"other@example.com", "primary": true, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "github", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}

func (ts *ExternalTestSuite) TestSignupExternalGitHubErrorWhenVerifiedFalse() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"github@example.com", "primary": true, "verified": false}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "github", code, "")

	v, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.Equal("unauthorized_client", v.Get("error"))
	ts.Equal("401", v.Get("error_code"))
	ts.Equal("Unverified email with github", v.Get("error_description"))
	assertAuthorizationFailure(ts, u, "", "", "")
}

func (ts *ExternalTestSuite) TestSignupExternalGitHubErrorWhenUserBanned() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"github@example.com", "primary": true, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "github", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "github@example.com", "GitHub Test", "123", "http://example.com/avatar")

	user, err := models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "github@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	t := time.Now().Add(24 * time.Hour)
	user.BannedUntil = &t
	require.NoError(ts.T(), ts.API.db.UpdateOnly(user, "banned_until"))

	u = performAuthorization(ts, "github", code, "")
	assertAuthorizationFailure(ts, u, "User is unauthorized", "unauthorized_client", "")
}
