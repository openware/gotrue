package mailer

import (
	"fmt"
	"net/mail"

	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/mailme"
)

// TemplateMailer will send mail and use templates from the site for easy mail styling
type TemplateMailer struct {
	SiteURL string
	Config  *conf.Configuration
	Mailer  *mailme.Mailer
}

var configFile = ""

const defaultInviteMail = `<h2>You have been invited</h2>

<p>You have been invited to create a user on {{ .SiteURL }}. Follow this link to accept the invite:</p>
<p><a href="{{ .ConfirmationURL }}">Accept the invite</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>`

const defaultConfirmationMail = `<h2>Confirm your email</h2>

<p>Follow this link to confirm your email:</p>
<p><a href="{{ .ConfirmationURL }}">Confirm your email address</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>
`

const defaultRecoveryMail = `<h2>Reset password</h2>

<p>Follow this link to reset the password for your user:</p>
<p><a href="{{ .ConfirmationURL }}">Reset password</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>`

const defaultMagicLinkMail = `<h2>Magic Link</h2>

<p>Follow this link to login:</p>
<p><a href="{{ .ConfirmationURL }}">Log In</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>`

const defaultEmailChangeMail = `<h2>Confirm email address change</h2>

<p>Follow this link to confirm the update of your email address from {{ .Email }} to {{ .NewEmail }}:</p>
<p><a href="{{ .ConfirmationURL }}">Change email address</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>`

// ValidateEmail returns nil if the email is valid,
// otherwise an error indicating the reason it is invalid
func (m TemplateMailer) ValidateEmail(email string) error {
  _, err := mail.ParseAddress(email)
  return err
}

// InviteMail sends a invite mail to a new user
func (m *TemplateMailer) InviteMail(user *models.User, referrerURL string) error {
	globalConfig, err := conf.LoadGlobal(configFile)
	if err != nil {
		return err
	}

	redirectParam := ""
	if len(referrerURL) > 0 {
		redirectParam = "&redirect_to=" + referrerURL
	}

	url, err := getSiteURL(referrerURL, globalConfig.API.ExternalURL, m.Config.Mailer.URLPaths.Invite, "token="+user.ConfirmationToken+"&type=invite"+redirectParam)
	if err != nil {
		return err
	}
	data := map[string]interface{}{
		"SiteURL":         m.Config.SiteURL,
		"ConfirmationURL": url,
		"Email":           user.Email,
		"Token":           user.ConfirmationToken,
		"Data":            user.UserMetaData,
	}

	return m.Mailer.Mail(
		user.GetEmail(),
		string(withDefault(m.Config.Mailer.Subjects.Invite, "You have been invited")),
		m.Config.Mailer.Templates.Invite,
		defaultInviteMail,
		data,
	)
}

// ConfirmationMail sends a signup confirmation mail to a new user
func (m *TemplateMailer) ConfirmationMail(user *models.User, referrerURL string) error {
	globalConfig, err := conf.LoadGlobal(configFile)
	if err != nil {
		return err
	}

	redirectParam := ""
	if len(referrerURL) > 0 {
		redirectParam = "&redirect_to=" + referrerURL
	}

	url, err := getSiteURL(referrerURL, globalConfig.API.ExternalURL, m.Config.Mailer.URLPaths.Confirmation, "token="+user.ConfirmationToken+"&type=signup"+redirectParam)
	if err != nil {
		return err
	}
	data := map[string]interface{}{
		"SiteURL":         m.Config.SiteURL,
		"ConfirmationURL": url,
		"Email":           user.Email,
		"Token":           user.ConfirmationToken,
		"Data":            user.UserMetaData,
	}

	return m.Mailer.Mail(
		user.GetEmail(),
		string(withDefault(m.Config.Mailer.Subjects.Confirmation, "Confirm Your Email")),
		m.Config.Mailer.Templates.Confirmation,
		defaultConfirmationMail,
		data,
	)
}

// EmailChangeMail sends an email change confirmation mail to a user
func (m *TemplateMailer) EmailChangeMail(user *models.User, referrerURL string) error {
	type Email struct {
		Address  string
		Token    string
		Subject  string
		Template string
	}
	emails := []Email{
		{
			Address:  user.EmailChange,
			Token:    user.EmailChangeTokenNew,
			Subject:  string(withDefault(m.Config.Mailer.Subjects.EmailChange, "Confirm Email Change")),
			Template: m.Config.Mailer.Templates.Confirmation,
		},
	}

	if m.Config.Mailer.SecureEmailChangeEnabled {
		emails = append(emails, Email{
			Address:  user.GetEmail(),
			Token:    user.EmailChangeTokenCurrent,
			Subject:  string(withDefault(m.Config.Mailer.Subjects.Confirmation, "Confirm Email Address")),
			Template: m.Config.Mailer.Templates.EmailChange,
		})
	}

	globalConfig, err := conf.LoadGlobal(configFile)
	if err != nil {
		return err
	}

	redirectParam := ""
	if len(referrerURL) > 0 {
		redirectParam = "&redirect_to=" + referrerURL
	}
	errors := make(chan error)
	for _, email := range emails {
		url, err := getSiteURL(
			referrerURL,
			globalConfig.API.ExternalURL,
			m.Config.Mailer.URLPaths.EmailChange,
			"token="+email.Token+"&type=email_change"+redirectParam,
		)
		if err != nil {
			return err
		}
		go func(address, token, template string) {
			data := map[string]interface{}{
				"SiteURL":         m.Config.SiteURL,
				"ConfirmationURL": url,
				"Email":           user.GetEmail(),
				"NewEmail":        user.EmailChange,
				"Token":           token,
				"Data":            user.UserMetaData,
			}
			errors <- m.Mailer.Mail(
				address,
				string(withDefault(m.Config.Mailer.Subjects.EmailChange, "Confirm Email Change")),
				template,
				defaultEmailChangeMail,
				data,
			)
		}(email.Address, email.Token, email.Template)
	}

	for i := 0; i < len(emails); i++ {
		e := <-errors
		if e != nil {
			return e
		}
	}

	return nil
}

// RecoveryMail sends a password recovery mail
func (m *TemplateMailer) RecoveryMail(user *models.User, referrerURL string) error {
	globalConfig, err := conf.LoadGlobal(configFile)
	if err != nil {
		return err
	}

	redirectParam := ""
	if len(referrerURL) > 0 {
		redirectParam = "&redirect_to=" + referrerURL
	}

	url, err := getSiteURL(referrerURL, globalConfig.API.ExternalURL, m.Config.Mailer.URLPaths.Recovery, "token="+user.RecoveryToken+"&type=recovery"+redirectParam)
	if err != nil {
		return err
	}
	data := map[string]interface{}{
		"SiteURL":         m.Config.SiteURL,
		"ConfirmationURL": url,
		"Email":           user.Email,
		"Token":           user.RecoveryToken,
		"Data":            user.UserMetaData,
	}

	return m.Mailer.Mail(
		user.GetEmail(),
		string(withDefault(m.Config.Mailer.Subjects.Recovery, "Reset Your Password")),
		m.Config.Mailer.Templates.Recovery,
		defaultRecoveryMail,
		data,
	)
}

// MagicLinkMail sends a login link mail
func (m *TemplateMailer) MagicLinkMail(user *models.User, referrerURL string) error {
	globalConfig, err := conf.LoadGlobal(configFile)
	if err != nil {
		return err
	}

	redirectParam := ""
	if len(referrerURL) > 0 {
		redirectParam = "&redirect_to=" + referrerURL
	}

	url, err := getSiteURL(referrerURL, globalConfig.API.ExternalURL, m.Config.Mailer.URLPaths.Recovery, "token="+user.RecoveryToken+"&type=magiclink"+redirectParam)
	if err != nil {
		return err
	}
	data := map[string]interface{}{
		"SiteURL":         m.Config.SiteURL,
		"ConfirmationURL": url,
		"Email":           user.Email,
		"Token":           user.RecoveryToken,
		"Data":            user.UserMetaData,
	}

	return m.Mailer.Mail(
		user.GetEmail(),
		string(withDefault(m.Config.Mailer.Subjects.MagicLink, "Your Magic Link")),
		m.Config.Mailer.Templates.MagicLink,
		defaultMagicLinkMail,
		data,
	)
}

// Send can be used to send one-off emails to users
func (m TemplateMailer) Send(user *models.User, subject, body string, data map[string]interface{}) error {
	return m.Mailer.Mail(
		user.GetEmail(),
		subject,
		"",
		body,
		data,
	)
}

// GetEmailActionLink returns a magiclink, recovery or invite link based on the actionType passed.
func (m TemplateMailer) GetEmailActionLink(user *models.User, actionType, referrerURL string) (string, error) {
	globalConfig, err := conf.LoadGlobal(configFile)
	if err != nil {
		return "", err
	}

	redirectParam := ""
	if len(referrerURL) > 0 {
		redirectParam = "&redirect_to=" + referrerURL
	}

	var url string
	switch actionType {
	case "magiclink":
		url, err = getSiteURL(referrerURL, globalConfig.API.ExternalURL, m.Config.Mailer.URLPaths.Recovery, "token="+user.RecoveryToken+"&type=magiclink"+redirectParam)
	case "recovery":
		url, err = getSiteURL(referrerURL, globalConfig.API.ExternalURL, m.Config.Mailer.URLPaths.Recovery, "token="+user.RecoveryToken+"&type=recovery"+redirectParam)
	case "invite":
		url, err = getSiteURL(referrerURL, globalConfig.API.ExternalURL, m.Config.Mailer.URLPaths.Invite, "token="+user.ConfirmationToken+"&type=invite"+redirectParam)
	case "signup":
		url, err = getSiteURL(referrerURL, globalConfig.API.ExternalURL, m.Config.Mailer.URLPaths.Confirmation, "token="+user.ConfirmationToken+"&type=signup"+redirectParam)
	default:
		return "", fmt.Errorf("Invalid email action link type: %s", actionType)
	}

	if err != nil {
		return "", err
	}

	return url, nil
}
