package conf

import (
	"crypto/rsa"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

const defaultMinPasswordLength int = 6

// OAuthProviderConfiguration holds all config related to external account providers.
type OAuthProviderConfiguration struct {
	ClientID    string `json:"client_id" split_words:"true"`
	Secret      string `json:"secret"`
	RedirectURI string `json:"redirect_uri" split_words:"true"`
	URL         string `json:"url"`
	ApiURL      string `json:"api_url"`
	Enabled     bool   `json:"enabled"`
}

type EmailProviderConfiguration struct {
	Enabled bool `json:"enabled" default:"true"`
}

type SamlProviderConfiguration struct {
	Enabled     bool   `json:"enabled"`
	MetadataURL string `json:"metadata_url" envconfig:"METADATA_URL"`
	APIBase     string `json:"api_base" envconfig:"API_BASE"`
	Name        string `json:"name"`
	SigningCert string `json:"signing_cert" envconfig:"SIGNING_CERT"`
	SigningKey  string `json:"signing_key" envconfig:"SIGNING_KEY"`
}

// DBConfiguration holds all the database related configuration.
type DBConfiguration struct {
	Driver         string `json:"driver" required:"true"`
	URL            string `json:"url" envconfig:"DATABASE_URL" required:"true"`
	MigrationsPath string `json:"migrations_path" split_words:"true" default:"./migrations"`
}

// JWTConfiguration holds all the JWT related configuration.
type JWTConfiguration struct {
	Algorithm        string   `json:"algorithm" default:"HS256"`
	Secret           string   `json:"secret" required:"true"`
	Exp              int      `json:"exp"`
	Aud              string   `json:"aud"`
	AdminGroupName   string   `json:"admin_group_name" split_words:"true"`
	AdminRoles       []string `json:"admin_roles" split_words:"true"`
	DefaultGroupName string   `json:"default_group_name" split_words:"true"`
	pKey             *rsa.PrivateKey
}

// GlobalConfiguration holds all the configuration that applies to all instances.
type GlobalConfiguration struct {
	API struct {
		Host            string
		Port            int `envconfig:"PORT" default:"8081"`
		Endpoint        string
		RequestIDHeader string `envconfig:"REQUEST_ID_HEADER"`
		ExternalURL     string `json:"external_url" envconfig:"API_EXTERNAL_URL"`
	}
	DB                 DBConfiguration
	External           ProviderConfiguration
	Logging            LoggingConfig `envconfig:"LOG"`
	OperatorToken      string        `split_words:"true" required:"false"`
	MultiInstanceMode  bool
	Tracing            TracingConfig
	SMTP               SMTPConfiguration
	RateLimitHeader    string  `split_words:"true"`
	RateLimitEmailSent float64 `split_words:"true" default:"30"`
}

// EmailContentConfiguration holds the configuration for emails, both subjects and template URLs.
type EmailContentConfiguration struct {
	Invite       string `json:"invite"`
	Confirmation string `json:"confirmation"`
	Recovery     string `json:"recovery"`
	EmailChange  string `json:"email_change" split_words:"true"`
	MagicLink    string `json:"magic_link" split_words:"true"`
}

type ProviderConfiguration struct {
	Apple       OAuthProviderConfiguration `json:"apple"`
	Azure       OAuthProviderConfiguration `json:"azure"`
	Bitbucket   OAuthProviderConfiguration `json:"bitbucket"`
	Discord     OAuthProviderConfiguration `json:"discord"`
	Facebook    OAuthProviderConfiguration `json:"facebook"`
	Github      OAuthProviderConfiguration `json:"github"`
	Gitlab      OAuthProviderConfiguration `json:"gitlab"`
	Google      OAuthProviderConfiguration `json:"google"`
	Notion      OAuthProviderConfiguration `json:"notion"`
	Linkedin    OAuthProviderConfiguration `json:"linkedin"`
	Spotify     OAuthProviderConfiguration `json:"spotify"`
	Slack       OAuthProviderConfiguration `json:"slack"`
	Twitter     OAuthProviderConfiguration `json:"twitter"`
	Twitch      OAuthProviderConfiguration `json:"twitch"`
	Email       EmailProviderConfiguration `json:"email"`
	Phone       PhoneProviderConfiguration `json:"phone"`
	Saml        SamlProviderConfiguration  `json:"saml"`
	Zoom        OAuthProviderConfiguration `json:"zoom"`
	IosBundleId string                     `json:"ios_bundle_id" split_words:"true"`
	RedirectURL string                     `json:"redirect_url"`
}

type SMTPConfiguration struct {
	MaxFrequency time.Duration `json:"max_frequency" split_words:"true"`
	Host         string        `json:"host"`
	Port         int           `json:"port,omitempty" default:"587"`
	User         string        `json:"user"`
	Pass         string        `json:"pass,omitempty"`
	AdminEmail   string        `json:"admin_email" split_words:"true"`
	SenderName   string        `json:"sender_name" split_words:"true"`
}

type MailerConfiguration struct {
	Autoconfirm              bool                      `json:"autoconfirm"`
	Subjects                 EmailContentConfiguration `json:"subjects"`
	Templates                EmailContentConfiguration `json:"templates"`
	URLPaths                 EmailContentConfiguration `json:"url_paths"`
	SecureEmailChangeEnabled bool                      `json:"secure_email_change_enabled" split_words:"true" default:"true"`
	OtpExp                   uint                      `json:"otp_exp" split_words:"true"`
}

type PhoneProviderConfiguration struct {
	Enabled bool `json:"enabled"`
}

type SmsProviderConfiguration struct {
	Autoconfirm  bool                             `json:"autoconfirm"`
	MaxFrequency time.Duration                    `json:"max_frequency" split_words:"true"`
	OtpExp       uint                             `json:"otp_exp" split_words:"true"`
	OtpLength    int                              `json:"otp_length" split_words:"true"`
	Provider     string                           `json:"provider"`
	Template     string                           `json:"template"`
	Twilio       TwilioProviderConfiguration      `json:"twilio"`
	Messagebird  MessagebirdProviderConfiguration `json:"messagebird"`
	Textlocal    TextlocalProviderConfiguration   `json:"textlocal"`
	Vonage       VonageProviderConfiguration      `json:"vonage"`
}

type TwilioProviderConfiguration struct {
	AccountSid        string `json:"account_sid" split_words:"true"`
	AuthToken         string `json:"auth_token" split_words:"true"`
	MessageServiceSid string `json:"message_service_sid" split_words:"true"`
}

type MessagebirdProviderConfiguration struct {
	AccessKey  string `json:"access_key" split_words:"true"`
	Originator string `json:"originator" split_words:"true"`
}

type TextlocalProviderConfiguration struct {
	ApiKey string `json:"api_key" split_words:"true"`
	Sender string `json:"sender" split_words:"true"`
}

type VonageProviderConfiguration struct {
	ApiKey    string `json:"api_key" split_words:"true"`
	ApiSecret string `json:"api_secret" split_words:"true"`
	From      string `json:"from" split_words:"true"`
}

type CaptchaConfiguration struct {
	Enabled  bool   `json:"enabled" default:"false"`
	Provider string `json:"provider" default:"hcaptcha"`
	Secret   string `json:"provider_secret"`
}

type SecurityConfiguration struct {
	Captcha                     CaptchaConfiguration `json:"captcha"`
	RefreshTokenRotationEnabled bool                 `json:"refresh_token_rotation_enabled" split_words:"true" default:"true"`
}

// Configuration holds all the per-instance configuration.
type Configuration struct {
	SiteURL             string                   `json:"site_url" split_words:"true" required:"true"`
	URIAllowList        []string                 `json:"uri_allow_list" split_words:"true"`
	PasswordMinLength   int                      `json:"password_min_length" split_words:"true"`
	JWT                 JWTConfiguration         `json:"jwt"`
	SMTP                SMTPConfiguration        `json:"smtp"`
	Mailer              MailerConfiguration      `json:"mailer"`
	External            ProviderConfiguration    `json:"external"`
	Sms                 SmsProviderConfiguration `json:"sms"`
	DisableSignup       bool                     `json:"disable_signup" split_words:"true"`
	FirstUserSuperAdmin bool                     `json:"first_user_super_admin" split_words:"true"`
	Webhook             WebhookConfig            `json:"webhook" split_words:"true"`
	Security            SecurityConfiguration    `json:"security"`
	Cookie              struct {
		Key      string `json:"key"`
		Domain   string `json:"domain"`
		Duration int    `json:"duration"`
	} `json:"cookies"`
}

func loadEnvironment(filename string) error {
	var err error
	if filename != "" {
		err = godotenv.Load(filename)
	} else {
		err = godotenv.Load()
		// handle if .env file does not exist, this is OK
		if os.IsNotExist(err) {
			return nil
		}
	}
	return err
}

type WebhookConfig struct {
	URL        string   `json:"url"`
	Retries    int      `json:"retries"`
	TimeoutSec int      `json:"timeout_sec"`
	Secret     string   `json:"secret"`
	Events     []string `json:"events"`
}

func (w *WebhookConfig) HasEvent(event string) bool {
	for _, name := range w.Events {
		if event == name {
			return true
		}
	}
	return false
}

// LoadGlobal loads configuration from file and environment variables.
func LoadGlobal(filename string) (*GlobalConfiguration, error) {
	if err := loadEnvironment(filename); err != nil {
		return nil, err
	}

	config := new(GlobalConfiguration)
	if err := envconfig.Process("gotrue", config); err != nil {
		return nil, err
	}

	if _, err := ConfigureLogging(&config.Logging); err != nil {
		return nil, err
	}

	ConfigureTracing(&config.Tracing)

	if config.SMTP.MaxFrequency == 0 {
		config.SMTP.MaxFrequency = 1 * time.Minute
	}
	return config, nil
}

// LoadConfig loads per-instance configuration.
func LoadConfig(filename string) (*Configuration, error) {
	if err := loadEnvironment(filename); err != nil {
		return nil, err
	}

	config := new(Configuration)
	if err := envconfig.Process("gotrue", config); err != nil {
		return nil, err
	}
	config.ApplyDefaults()
	return config, nil
}

// ApplyDefaults sets defaults for a Configuration
func (config *Configuration) ApplyDefaults() {
	if config.JWT.AdminGroupName == "" {
		config.JWT.AdminGroupName = "admin"
	}

	if config.JWT.AdminRoles == nil || len(config.JWT.AdminRoles) == 0 {
		config.JWT.AdminRoles = []string{"service_role", "supabase_admin"}
	}

	if config.JWT.Exp == 0 {
		config.JWT.Exp = 3600
	}

	if config.Mailer.URLPaths.Invite == "" {
		config.Mailer.URLPaths.Invite = "/"
	}

	if config.Mailer.URLPaths.Confirmation == "" {
		config.Mailer.URLPaths.Confirmation = "/"
	}

	if config.Mailer.URLPaths.Recovery == "" {
		config.Mailer.URLPaths.Recovery = "/"
	}

	if config.Mailer.URLPaths.EmailChange == "" {
		config.Mailer.URLPaths.EmailChange = "/"
	}

	if config.Mailer.OtpExp == 0 {
		config.Mailer.OtpExp = 86400 // 1 day
	}

	if config.SMTP.MaxFrequency == 0 {
		config.SMTP.MaxFrequency = 1 * time.Minute
	}

	if config.Sms.MaxFrequency == 0 {
		config.Sms.MaxFrequency = 1 * time.Minute
	}

	if config.Sms.OtpExp == 0 {
		config.Sms.OtpExp = 60
	}

	if config.Sms.OtpLength == 0 || config.Sms.OtpLength < 6 || config.Sms.OtpLength > 10 {
		// 6-digit otp by default
		config.Sms.OtpLength = 6
	}

	if len(config.Sms.Template) == 0 {
		config.Sms.Template = ""
	}

	if config.Cookie.Key == "" {
		config.Cookie.Key = "sb"
	}

	if config.Cookie.Domain == "" {
		config.Cookie.Domain = ""
	}

	if config.Cookie.Duration == 0 {
		config.Cookie.Duration = 86400
	}

	if config.URIAllowList == nil {
		config.URIAllowList = []string{}
	}

	if config.PasswordMinLength < defaultMinPasswordLength {
		config.PasswordMinLength = defaultMinPasswordLength
	}

	config.JWT.InitializeSigningSecret()
}

func (config *Configuration) Value() (driver.Value, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return driver.Value(""), err
	}
	return driver.Value(string(data)), nil
}

func (config *Configuration) Scan(src interface{}) error {
	var source []byte
	switch v := src.(type) {
	case string:
		source = []byte(v)
	case []byte:
		source = v
	default:
		return errors.New("Invalid data type for Configuration")
	}

	if len(source) == 0 {
		source = []byte("{}")
	}
	return json.Unmarshal(source, &config)
}

func (o *OAuthProviderConfiguration) Validate() error {
	if !o.Enabled {
		return errors.New("Provider is not enabled")
	}
	if o.ClientID == "" {
		return errors.New("Missing Oauth client ID")
	}
	if o.Secret == "" {
		return errors.New("Missing Oauth secret")
	}
	if o.RedirectURI == "" {
		return errors.New("Missing redirect URI")
	}
	return nil
}

func (t *TwilioProviderConfiguration) Validate() error {
	if t.AccountSid == "" {
		return errors.New("Missing Twilio account SID")
	}
	if t.AuthToken == "" {
		return errors.New("Missing Twilio auth token")
	}
	if t.MessageServiceSid == "" {
		return errors.New("Missing Twilio message service SID or Twilio phone number")
	}
	return nil
}

func (t *MessagebirdProviderConfiguration) Validate() error {
	if t.AccessKey == "" {
		return errors.New("Missing Messagebird access key")
	}
	if t.Originator == "" {
		return errors.New("Missing Messagebird originator")
	}
	return nil
}

func (t *TextlocalProviderConfiguration) Validate() error {
	if t.ApiKey == "" {
		return errors.New("Missing Textlocal API key")
	}
	if t.Sender == "" {
		return errors.New("Missing Textlocal sender")
	}
	return nil
}

func (t *VonageProviderConfiguration) Validate() error {
	if t.ApiKey == "" {
		return errors.New("Missing Vonage API key")
	}
	if t.ApiSecret == "" {
		return errors.New("Missing Vonage API secret")
	}
	if t.From == "" {
		return errors.New("Missing Vonage 'from' parameter")
	}
	return nil
}

func (j *JWTConfiguration) InitializeSigningSecret() {
	if j.Algorithm == "RS256" {
		pemPrivateKey, err := base64.URLEncoding.DecodeString(j.Secret)
		if err != nil {
			panic(err)
		}

		key, err := jwt.ParseRSAPrivateKeyFromPEM(pemPrivateKey)
		if err != nil {
			panic(err)
		}

		j.pKey = key
	}
}

func (j *JWTConfiguration) GetSigningKey() interface{} {
	if j.Algorithm == "RS256" {
		return j.pKey
	}

	return []byte(j.Secret)
}

func (j *JWTConfiguration) GetVerificationKey() interface{} {
	if j.Algorithm == "RS256" {
		return j.pKey.Public()
	}

	return []byte(j.Secret)
}

func (j *JWTConfiguration) GetSigningMethod() jwt.SigningMethod {
	switch j.Algorithm {
	case "RS256":
		return jwt.SigningMethodRS256
	default:
		return jwt.SigningMethodHS256
	}
}
