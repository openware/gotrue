# GoTrue - User management for APIs

GoTrue is a small open-source API written in golang, that can act as a self-standing
API service for handling user registration and authentication for JAM projects.

It's based on OAuth2 and JWT and will handle user signup, authentication and custom
user data.

## Quick Start

Create a `.env` file to store your own custom env vars. See [`example.env`](example.env)

1. Start the local postgres database in a postgres container: `./hack/postgresd.sh` 
2. Build the gotrue binary: `make build` . You should see an output like this:
```
go build -ldflags "-X github.com/supabase/gotrue/cmd.Version=`git rev-parse HEAD`"
GOOS=linux GOARCH=arm64 go build -ldflags "-X github.com/supabase/gotrue/cmd.Version=`git rev-parse HEAD`" -o gotrue-arm64
```
3. Execute the gotrue binary: `./gotrue` (if you're on x86) `./gotrue-arm64` (if you're on arm)

## Configuration

You may configure GoTrue using either a configuration file named `.env`,
environment variables, or a combination of both. Environment variables are prefixed with `GOTRUE_`, and will always have precedence over values provided via file.

### Top-Level

```properties
GOTRUE_SITE_URL=https://example.netlify.com/
```

`SITE_URL` - `string` **required**

The base URL your site is located at. Currently used in combination with other settings to construct URLs used in emails. Any URI that shares a host with `SITE_URL` is a permitted value for `redirect_to` params (see `/authorize` etc.).

`URI_ALLOW_LIST` - `string`

A comma separated list of URIs (e.g. "https://supabase.io/welcome,io.supabase.gotruedemo://logincallback") which are permitted as valid `redirect_to` destinations, in addition to SITE_URL. Defaults to [].

`OPERATOR_TOKEN` - `string` _Multi-instance mode only_

The shared secret with an operator (usually Netlify) for this microservice. Used to verify requests have been proxied through the operator and
the payload values can be trusted.

`DISABLE_SIGNUP` - `bool`

When signup is disabled the only way to create new users is through invites. Defaults to `false`, all signups enabled.

`GOTRUE_EXTERNAL_EMAIL_ENABLED` - `bool`

Use this to disable email signups (users can still use external oauth providers to sign up / sign in)

`GOTRUE_EXTERNAL_PHONE_ENABLED` - `bool`

Use this to disable phone signups (users can still use external oauth providers to sign up / sign in)

`GOTRUE_RATE_LIMIT_HEADER` - `string`

Header on which to rate limit the `/token` endpoint.

`GOTRUE_RATE_LIMIT_EMAIL_SENT` - `string`

Rate limit the number of emails sent per hr on the following endpoints: `/signup`, `/invite`, `/magiclink`, `/recover`, `/otp`, & `/user`.

`GOTRUE_PASSWORD_MIN_LENGTH` - `int`

Minimum password length, defaults to 6.

### API

```properties
GOTRUE_API_HOST=localhost
PORT=9999
```

`API_HOST` - `string`

Hostname to listen on.

`PORT` (no prefix) / `API_PORT` - `number`

Port number to listen on. Defaults to `8081`.

`API_ENDPOINT` - `string` _Multi-instance mode only_

Controls what endpoint Netlify can access this API on.

`REQUEST_ID_HEADER` - `string`

If you wish to inherit a request ID from the incoming request, specify the name in this value.

### Database

```properties
GOTRUE_DB_DRIVER=mysql
DATABASE_URL=root@localhost/gotrue
```

`DB_DRIVER` - `string` **required**

Chooses what dialect of database you want. Must be `mysql`.

`DATABASE_URL` (no prefix) / `DB_DATABASE_URL` - `string` **required**

Connection string for the database.

`DB_NAMESPACE` - `string`

Adds a prefix to all table names.

**Migrations Note**

Migrations are not applied automatically, so you will need to run them after
you've built gotrue.

- If built locally: `./gotrue migrate`
- Using Docker: `docker run --rm gotrue gotrue migrate`

### Logging

```properties
LOG_LEVEL=debug # available without GOTRUE prefix (exception)
GOTRUE_LOG_FILE=/var/log/go/gotrue.log
```

`LOG_LEVEL` - `string`

Controls what log levels are output. Choose from `panic`, `fatal`, `error`, `warn`, `info`, or `debug`. Defaults to `info`.

`LOG_FILE` - `string`

If you wish logs to be written to a file, set `log_file` to a valid file path.

### Opentracing

Currently, only the Datadog tracer is supported.

```properties
GOTRUE_TRACING_ENABLED=true
GOTRUE_TRACING_HOST=127.0.0.1
GOTRUE_TRACING_PORT=8126
GOTRUE_TRACING_TAGS="tag1:value1,tag2:value2"
GOTRUE_SERVICE_NAME="gotrue"
```

`TRACING_ENABLED` - `bool`

Whether tracing is enabled or not. Defaults to `false`.

`TRACING_HOST` - `bool`

The tracing destination.

`TRACING_PORT` - `bool`

The port for the tracing host.

`TRACING_TAGS` - `string`

A comma separated list of key:value pairs. These key value pairs will be added as tags to all opentracing spans.

`SERVICE_NAME` - `string`

The name to use for the service.

### JSON Web Tokens (JWT)

```properties
GOTRUE_JWT_SECRET=supersecretvalue
GOTRUE_JWT_ALGORITHM=RS256
GOTRUE_JWT_EXP=3600
GOTRUE_JWT_AUD=netlify
```
`JWT_ALGORITHM` - `string`

The signing algorithm for the JWT. Defaults to HS256.

`JWT_SECRET` - `string` **required**

The secret used to sign JWT tokens with. If signing alogrithm is RS256, secret has to be Base64 encoded RSA private key.

`JWT_EXP` - `number`

How long tokens are valid for, in seconds. Defaults to 3600 (1 hour).

`JWT_AUD` - `string`

The default JWT audience. Use audiences to group users.

`JWT_ADMIN_GROUP_NAME` - `string`

The name of the admin group (if enabled). Defaults to `admin`.

`JWT_DEFAULT_GROUP_NAME` - `string`

The default group to assign all new users to.

### External Authentication Providers

We support `apple`, `azure`, `bitbucket`, `discord`, `facebook`, `github`, `gitlab`, `google`, `linkedin`, `notion`, `spotify`, `slack`, `twitch` and `twitter` for external authentication.

Use the names as the keys underneath `external` to configure each separately.

```properties
GOTRUE_EXTERNAL_GITHUB_ENABLED=true
GOTRUE_EXTERNAL_GITHUB_CLIENT_ID=myappclientid
GOTRUE_EXTERNAL_GITHUB_SECRET=clientsecretvaluessssh
GOTRUE_EXTERNAL_GITHUB_REDIRECT_URI=http://localhost:3000/callback
```

No external providers are required, but you must provide the required values if you choose to enable any.

`EXTERNAL_X_ENABLED` - `bool`

Whether this external provider is enabled or not

`EXTERNAL_X_CLIENT_ID` - `string` **required**

The OAuth2 Client ID registered with the external provider.

`EXTERNAL_X_SECRET` - `string` **required**

The OAuth2 Client Secret provided by the external provider when you registered.

`EXTERNAL_X_REDIRECT_URI` - `string` **required**

The URI a OAuth2 provider will redirect to with the `code` and `state` values.

`EXTERNAL_X_URL` - `string`

The base URL used for constructing the URLs to request authorization and access tokens. Used by `gitlab` only. Defaults to `https://gitlab.com`.

#### Apple OAuth

To try out external authentication with Apple locally, you will need to do the following:

1. Remap localhost to \<my_custom_dns \> in your `/etc/hosts` config.
2. Configure gotrue to serve HTTPS traffic over localhost by replacing `ListenAndServe` in [api.go](api/api.go) with:
   ```
      func (a *API) ListenAndServe(hostAndPort string) {
        log := logrus.WithField("component", "api")
        path, err := os.Getwd()
        if err != nil {
          log.Println(err)
        }
        server := &http.Server{
          Addr:    hostAndPort,
          Handler: a.handler,
        }
        done := make(chan struct{})
        defer close(done)
        go func() {
          waitForTermination(log, done)
          ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
          defer cancel()
          server.Shutdown(ctx)
        }()
        if err := server.ListenAndServeTLS("PATH_TO_CRT_FILE", "PATH_TO_KEY_FILE"); err != http.ErrServerClosed {
          log.WithError(err).Fatal("http server listen failed")
        }
    }
   ```
3. Generate the crt and key file. See [here](https://www.freecodecamp.org/news/how-to-get-https-working-on-your-local-development-environment-in-5-minutes-7af615770eec/) for more information.
4. Generate the `GOTRUE_EXTERNAL_APPLE_SECRET` by following this [post](https://medium.com/identity-beyond-borders/how-to-configure-sign-in-with-apple-77c61e336003)!

### E-Mail

Sending email is not required, but highly recommended for password recovery.
If enabled, you must provide the required values below.

```properties
GOTRUE_SMTP_HOST=smtp.mandrillapp.com
GOTRUE_SMTP_PORT=587
GOTRUE_SMTP_USER=smtp-delivery@example.com
GOTRUE_SMTP_PASS=correcthorsebatterystaple
GOTRUE_SMTP_ADMIN_EMAIL=support@example.com
GOTRUE_MAILER_SUBJECTS_CONFIRMATION="Please confirm"
```

`SMTP_ADMIN_EMAIL` - `string` **required**

The `From` email address for all emails sent.

`SMTP_HOST` - `string` **required**

The mail server hostname to send emails through.

`SMTP_PORT` - `number` **required**

The port number to connect to the mail server on.

`SMTP_USER` - `string`

If the mail server requires authentication, the username to use.

`SMTP_PASS` - `string`

If the mail server requires authentication, the password to use.

`SMTP_MAX_FREQUENCY` - `number`

Controls the minimum amount of time that must pass before sending another signup confirmation or password reset email. The value is the number of seconds. Defaults to 900 (15 minutes).

`SMTP_SENDER_NAME` - `string`

Sets the name of the sender. Defaults to the `SMTP_ADMIN_EMAIL` if not used.

`MAILER_AUTOCONFIRM` - `bool`

If you do not require email confirmation, you may set this to `true`. Defaults to `false`.

`MAILER_OTP_EXP` - `number`

Controls the duration an email link or otp is valid for.

`MAILER_URLPATHS_INVITE` - `string`

URL path to use in the user invite email. Defaults to `/`.

`MAILER_URLPATHS_CONFIRMATION` - `string`

URL path to use in the signup confirmation email. Defaults to `/`.

`MAILER_URLPATHS_RECOVERY` - `string`

URL path to use in the password reset email. Defaults to `/`.

`MAILER_URLPATHS_EMAIL_CHANGE` - `string`

URL path to use in the email change confirmation email. Defaults to `/`.

`MAILER_SUBJECTS_INVITE` - `string`

Email subject to use for user invite. Defaults to `You have been invited`.

`MAILER_SUBJECTS_CONFIRMATION` - `string`

Email subject to use for signup confirmation. Defaults to `Confirm Your Signup`.

`MAILER_SUBJECTS_RECOVERY` - `string`

Email subject to use for password reset. Defaults to `Reset Your Password`.

`MAILER_SUBJECTS_MAGIC_LINK` - `string`

Email subject to use for magic link email. Defaults to `Your Magic Link`.

`MAILER_SUBJECTS_EMAIL_CHANGE` - `string`

Email subject to use for email change confirmation. Defaults to `Confirm Email Change`.

`MAILER_TEMPLATES_INVITE` - `string`

URL path to an email template to use when inviting a user.
`SiteURL`, `Email`, and `ConfirmationURL` variables are available.

Default Content (if template is unavailable):

```html
<h2>You have been invited</h2>

<p>
  You have been invited to create a user on {{ .SiteURL }}. Follow this link to
  accept the invite:
</p>
<p><a href="{{ .ConfirmationURL }}">Accept the invite</a></p>
```

`MAILER_TEMPLATES_CONFIRMATION` - `string`

URL path to an email template to use when confirming a signup.
`SiteURL`, `Email`, and `ConfirmationURL` variables are available.

Default Content (if template is unavailable):

```html
<h2>Confirm your signup</h2>

<p>Follow this link to confirm your user:</p>
<p><a href="{{ .ConfirmationURL }}">Confirm your mail</a></p>
```

`MAILER_TEMPLATES_RECOVERY` - `string`

URL path to an email template to use when resetting a password.
`SiteURL`, `Email`, and `ConfirmationURL` variables are available.

Default Content (if template is unavailable):

```html
<h2>Reset Password</h2>

<p>Follow this link to reset the password for your user:</p>
<p><a href="{{ .ConfirmationURL }}">Reset Password</a></p>
```

`MAILER_TEMPLATES_MAGIC_LINK` - `string`

URL path to an email template to use when sending magic link.
`SiteURL`, `Email`, and `ConfirmationURL` variables are available.

Default Content (if template is unavailable):

```html
<h2>Magic Link</h2>

<p>Follow this link to login:</p>
<p><a href="{{ .ConfirmationURL }}">Log In</a></p>
```

`MAILER_TEMPLATES_EMAIL_CHANGE` - `string`

URL path to an email template to use when confirming the change of an email address.
`SiteURL`, `Email`, `NewEmail`, and `ConfirmationURL` variables are available.

Default Content (if template is unavailable):

```html
<h2>Confirm Change of Email</h2>

<p>
  Follow this link to confirm the update of your email from {{ .Email }} to {{
  .NewEmail }}:
</p>
<p><a href="{{ .ConfirmationURL }}">Change Email</a></p>
```

`WEBHOOK_URL` - `string`

Url of the webhook receiver endpoint. This will be called when events like `validate`, `signup` or `login` occur.

`WEBHOOK_SECRET` - `string`

Shared secret to authorize webhook requests. This secret signs the [JSON Web Signature](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41) of the request. You _should_ use this to verify the integrity of the request. Otherwise others can feed your webhook receiver with fake data.

`WEBHOOK_RETRIES` - `number`

How often GoTrue should try a failed hook.

`WEBHOOK_TIMEOUT_SEC` - `number`

Time between retries (in seconds).

`WEBHOOK_EVENTS` - `list`

Which events should trigger a webhook. You can provide a comma separated list.
For example to listen to all events, provide the values `validate,signup,login`.

### Phone Auth

`SMS_AUTOCONFIRM` - `bool`

If you do not require phone confirmation, you may set this to `true`. Defaults to `false`.

`SMS_MAX_FREQUENCY` - `number`

Controls the minimum amount of time that must pass before sending another sms otp. The value is the number of seconds. Defaults to 60 (1 minute)).

`SMS_OTP_EXP` - `number`

Controls the duration an sms otp is valid for.

`SMS_OTP_LENGTH` - `number`

Controls the number of digits of the sms otp sent.

`SMS_PROVIDER` - `string`

Available options are: `twilio`, `messagebird`, `textlocal`, and `vonage`

Then you can use your [twilio credentials](https://www.twilio.com/docs/usage/requests-to-twilio#credentials):

- `SMS_TWILIO_ACCOUNT_SID`
- `SMS_TWILIO_AUTH_TOKEN`
- `SMS_TWILIO_MESSAGE_SERVICE_SID` - can be set to your twilio sender mobile number

Or Messagebird credentials, which can be obtained in the [Dashboard](https://dashboard.messagebird.com/en/developers/access):
- `SMS_MESSAGEBIRD_ACCESS_KEY` - your Messagebird access key
- `SMS_MESSAGEBIRD_ORIGINATOR` - SMS sender (your Messagebird phone number with + or company name)

### CAPTCHA

- If enabled, CAPTCHA will check the request body for the `hcaptcha_token` field and make a verification request to the CAPTCHA provider.

`SECURITY_CAPTCHA_ENABLED` - `string`

Whether captcha middleware is enabled

`SECURITY_CAPTCHA_PROVIDER` - `string`

for now the only option supported is: `hcaptcha`

`SECURITY_CAPTCHA_SECRET` - `string`

Retrieve from hcaptcha account

## Endpoints

GoTrue exposes the following endpoints:

### **GET /settings**

Returns the publicly available settings for this gotrue instance.

```json
{
  "external": {
    "apple": true,
    "azure": true,
    "bitbucket": true,
    "discord": true,
    "facebook": true,
    "github": true,
    "gitlab": true,
    "google": true,
    "linkedin": true,
    "notion": true,
    "slack": true,
    "spotify": true,
    "twitch": true,
    "twitter": true
  },
  "disable_signup": false,
  "autoconfirm": false
}
```

### **POST, PUT /admin/users/<user_id>**

Creates (POST) or Updates (PUT) the user based on the `user_id` specified. The `ban_duration` field accepts the following time units: "ns", "us", "ms", "s", "m", "h". See [`time.ParseDuration`](https://pkg.go.dev/time#ParseDuration) for more details on the format used.

```js
headers:
{
  "Authorization": "Bearer eyJhbGciOiJI...M3A90LCkxxtX9oNP9KZO" // admin role required
}

body:
{
  "role": "test-user",
  "email": "email@example.com",
  "phone": "12345678",
  "password": "secret", // only if type = signup
  "email_confirm": true,
  "phone_confirm": true,
  "user_metadata": {},
  "app_metadata": {},
  "ban_duration": "24h" or "none" // to unban a user
}
```

### **POST /admin/generate_link**

Returns the corresponding email action link based on the type specified.

```js
headers:
{
  "Authorization": "Bearer eyJhbGciOiJI...M3A90LCkxxtX9oNP9KZO" // admin role required
}

body:
{
  "type": "signup" or "magiclink" or "recovery" or "invite",
  "email": "email@example.com",
  "password": "secret", // only if type = signup
  "data": {
    ...
  }, // only if type = signup
  "redirect_to": "https://supabase.io" // Redirect URL to send the user to after an email action. Defaults to SITE_URL.

}
```

Returns

```js
{
  "action_link": "http://localhost:9999/verify?token=TOKEN&type=TYPE&redirect_to=REDIRECT_URL",
  ...
}
```

### **POST /signup**

Register a new user with an email and password.

```js
{
  "email": "email@example.com",
  "password": "secret"
}
```

returns:

```json
{
  "id": "11111111-2222-3333-4444-5555555555555",
  "email": "email@example.com",
  "confirmation_sent_at": "2016-05-15T20:49:40.882805774-07:00",
  "created_at": "2016-05-15T19:53:12.368652374-07:00",
  "updated_at": "2016-05-15T19:53:12.368652374-07:00"
}

// if sign up is a duplicate then faux data will be returned
// as to not leak information about whether a given email
// has an account with your service or not
```

Register a new user with a phone number and password.

```js
{
  "phone": "12345678", // follows the E.164 format
  "password": "secret"
}
```

Returns:

```json
{
  "id": "11111111-2222-3333-4444-5555555555555", // if duplicate sign up, this ID will be faux
  "phone": "12345678",
  "confirmation_sent_at": "2016-05-15T20:49:40.882805774-07:00",
  "created_at": "2016-05-15T19:53:12.368652374-07:00",
  "updated_at": "2016-05-15T19:53:12.368652374-07:00"
}
```

if AUTOCONFIRM is enabled and the sign up is a duplicate, then the endpoint will return:
```
{
  "code":400,
  "msg":"User already registered"
}
```

### **POST /invite**

Invites a new user with an email.
This endpoint requires the `service_role` or `supabase_admin` JWT set as an Auth Bearer header:

e.g.

```json
headers: {
  "Authorization" : "Bearer eyJhbGciOiJI...M3A90LCkxxtX9oNP9KZO"
}
```

```json
{
  "email": "email@example.com"
}
```

Returns:

```json
{
  "id": "11111111-2222-3333-4444-5555555555555",
  "email": "email@example.com",
  "confirmation_sent_at": "2016-05-15T20:49:40.882805774-07:00",
  "created_at": "2016-05-15T19:53:12.368652374-07:00",
  "updated_at": "2016-05-15T19:53:12.368652374-07:00",
  "invited_at": "2016-05-15T19:53:12.368652374-07:00"
}
```

### **POST /verify**

Verify a registration or a password recovery. Type can be `signup` or `recovery` or `invite`
and the `token` is a token returned from either `/signup` or `/recover`.

```json
{
  "type": "signup",
  "token": "confirmation-code-delivered-in-email"
}
```

`password` is required for signup verification if no existing password exists.

Returns:

```json
{
  "access_token": "jwt-token-representing-the-user",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "a-refresh-token",
  "type": "signup | recovery | invite"
}
```

Verify a phone signup or sms otp. Type should be set to `sms`.

```json
{
  "type": "sms",
  "token": "confirmation-otp-delivered-in-sms",
  "redirect_to": "https://supabase.io",
  "phone": "phone-number-sms-otp-was-delivered-to"
}
```

Returns:

```json
{
  "access_token": "jwt-token-representing-the-user",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "a-refresh-token"
}
```

### **GET /verify**

Verify a registration or a password recovery. Type can be `signup` or `recovery` or `magiclink` or `invite`
and the `token` is a token returned from either `/signup` or `/recover` or `/magiclink`.

query params:

```json
{
  "type": "signup",
  "token": "confirmation-code-delivered-in-email",
  "redirect_to": "https://supabase.io"
}
```

User will be logged in and redirected to:

```json
SITE_URL/#access_token=jwt-token-representing-the-user&token_type=bearer&expires_in=3600&refresh_token=a-refresh-token&type=invite
```

Your app should detect the query params in the fragment and use them to set the session (supabase-js does this automatically)

You can use the `type` param to redirect the user to a password set form in the case of `invite` or `recovery`,
or show an account confirmed/welcome message in the case of `signup`, or direct them to some additional onboarding flow

### **POST /otp**

One-Time-Password. Will deliver a magiclink or sms otp to the user depending on whether the request body contains an "email" or "phone" key.

If `"create_user": true`, user will not be automatically signed up if the user doesn't exist.

```js
{
  "phone": "12345678" // follows the E.164 format
  "create_user": true
}

OR

// exactly the same as /magiclink
{
  "email": "email@example.com"
  "create_user": true
}
```

Returns:

```
{}
```

### **POST /magiclink** (recommended to use /otp instead. See above.)

Magic Link. Will deliver a link (e.g. `/verify?type=magiclink&token=fgtyuf68ddqdaDd`) to the user based on
email address which they can use to redeem an access_token.

By default Magic Links can only be sent once every 60 seconds

```json
{
  "email": "email@example.com"
}
```

Returns:

```json
{}
```

when clicked the magic link will redirect the user to `<SITE_URL>#access_token=x&refresh_token=y&expires_in=z&token_type=bearer&type=magiclink` (see `/verify` above)

### **POST /recover**

Password recovery. Will deliver a password recovery mail to the user based on
email address.

By default recovery links can only be sent once every 60 seconds

```json
{
  "email": "email@example.com"
}
```

Returns:

```json
{}
```

### **POST /token**

This is an OAuth2 endpoint that currently implements
the password and refresh_token grant types

query params:

```
?grant_type=password
```

body:

```json
// Email login
{
  "email": "name@domain.com",
  "password": "somepassword"
}

// Phone login
{
  "phone": "12345678",
  "password": "somepassword"
}
```

or

query params:

```
grant_type=refresh_token
```

body:

```json
{
  "refresh_token": "a-refresh-token"
}
```

Once you have an access token, you can access the methods requiring authentication
by settings the `Authorization: Bearer YOUR_ACCESS_TOKEN_HERE` header.

Returns:

```json
{
  "access_token": "jwt-token-representing-the-user",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "a-refresh-token"
}
```

### **GET /user**

Get the JSON object for the logged in user (requires authentication)

Returns:

```json
{
  "id": "11111111-2222-3333-4444-5555555555555",
  "email": "email@example.com",
  "confirmation_sent_at": "2016-05-15T20:49:40.882805774-07:00",
  "created_at": "2016-05-15T19:53:12.368652374-07:00",
  "updated_at": "2016-05-15T19:53:12.368652374-07:00"
}
```

### **PUT /user**

Update a user (Requires authentication). Apart from changing email/password, this
method can be used to set custom user data. Changing the email will result in a magiclink being sent out.

```json
{
  "email": "new-email@example.com",
  "password": "new-password",
  "data": {
    "key": "value",
    "number": 10,
    "admin": false
  }
}
```

Returns:

```json
{
  "id": "11111111-2222-3333-4444-5555555555555",
  "email": "email@example.com",
  "email_change_sent_at": "2016-05-15T20:49:40.882805774-07:00",
  "created_at": "2016-05-15T19:53:12.368652374-07:00",
  "updated_at": "2016-05-15T19:53:12.368652374-07:00"
}
```

### **POST /logout**

Logout a user (Requires authentication).

This will revoke all refresh tokens for the user. Remember that the JWT tokens
will still be valid for stateless auth until they expires.

### **GET /authorize**

Get access_token from external oauth provider

query params:

```
provider=apple | azure | bitbucket | discord | facebook | github | gitlab | google | linkedin | notion | slack | spotify | twitch | twitter
scopes=<optional additional scopes depending on the provider (email and name are requested by default)>
```

Redirects to provider and then to `/callback`

For apple specific setup see: https://github.com/supabase/gotrue#apple-oauth

### **GET /callback**

External provider should redirect to here

Redirects to `<GOTRUE_SITE_URL>#access_token=<access_token>&refresh_token=<refresh_token>&provider_token=<provider_oauth_token>&expires_in=3600&provider=<provider_name>`
If additional scopes were requested then `provider_token` will be populated, you can use this to fetch additional data from the provider or interact with their services
### **POST /sign_challenge**

  This is an endpoint for user sign up with Asymmetric key.
  Currently implemets only sign up with Ethereum address( not public key).
  
  body:
  ```json
  // Sign up with Metamask browser extension
  {
    "key": "0x6BE46d7D863666546b77951D5dfffcF075F36E68",
    "algorithm": "ETH"
  }
  ```

  Returns:
  ```json
  {
    "challenge_token": "d188f5a4-f9d6-4ede-8cfd-2a45927b0edc"
  }
  ```
  Returned challenge token has to be signed with Metamask and sent back to /asymmetric_login
  
### **POST /asymmetric_login**

  This is an endpoint for user sign in with Asymmetric key.
  Accepts signed challenge token from `/sign_challenge` endpoint
  
  body:
  ```json
  // Login with with Metamask browser extension
  {
    "key": "0x6BE46d7D863666546b77951D5dfffcF075F36E68",
    "challenge_token_signature": "0x3129682f92a0f3f6ef648623c3256ae39ab16de4fefcc50c60a375c8dd224dde291f750d0fd3d475b403a00a631dd8979583b8d036d2e3b2408668a1b4ea6b321c"
  }
  ```

  Returns:
  ```json
  {
    "access_token": "jwt-token-representing-the-user",
    "token_type": "bearer",
    "expires_in": 3600,
    "refresh_token": "a-refresh-token"
  }
  ```
  
  Once you have an access token, you can access the methods requiring authentication
  by settings the `Authorization: Bearer YOUR_ACCESS_TOKEN_HERE` header.

