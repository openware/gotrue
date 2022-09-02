package mailer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplateMailer_ValidateEmail(t *testing.T) {
  testCases := []struct{
    Email string
    IsValid bool
  }{
    { Email: "test@gmail.com", IsValid: true},
    { Email: "test@openware.com", IsValid: true},
    { Email: "test@relay.firefox.com", IsValid: true},
    { Email: "test@abc", IsValid: true},
    { Email: "test", IsValid: false},
    { Email: "a@b@c@example.com", IsValid: false},
    { Email: "abc.example.com", IsValid: false},
    { Email: "a@b@c@example.com", IsValid: false},
  }

  for _, tt := range testCases {
    t.Run(tt.Email, func(t *testing.T) {
      mailer := &TemplateMailer{}
      err := mailer.ValidateEmail(tt.Email)
      
      if tt.IsValid {
        require.NoError(t, err)
      } else {
        require.Error(t, err)
      }
    })
  }
}
