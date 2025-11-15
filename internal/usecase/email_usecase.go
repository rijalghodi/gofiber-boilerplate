package usecase

import (
	"app/internal/config"
	"app/pkg/logger"
	"fmt"

	"github.com/go-gomail/gomail"
)

type EmailUsecase struct {
	Dialer *gomail.Dialer
}

func NewEmailUsecase() *EmailUsecase {
	return &EmailUsecase{
		Dialer: gomail.NewDialer(
			config.Env.SMTPGoogle.Host,
			config.Env.SMTPGoogle.Port,
			config.Env.SMTPGoogle.Email,
			config.Env.SMTPGoogle.Password,
		),
	}
}

func (s *EmailUsecase) SendEmail(to, subject, body string) error {
	mailer := gomail.NewMessage()
	mailer.SetHeader("From", config.Env.SMTPGoogle.Sender)
	mailer.SetHeader("To", to)
	mailer.SetHeader("Subject", subject)
	mailer.SetBody("text/plain", body)

	if err := s.Dialer.DialAndSend(mailer); err != nil {
		logger.Log.Errorf("Failed to send email: %v", err)
		return err
	}

	return nil
}

func (s *EmailUsecase) SendResetPasswordEmail(to, token string) error {
	subject := "Reset password"

	// TODO: replace this url with the link to the reset password page of your front-end app
	resetPasswordURL := fmt.Sprintf("http://link-to-app/reset-password?token=%s", token)
	body := fmt.Sprintf(`Dear user,

To reset your password, click on this link: %s

If you did not request any password resets, then ignore this email.`, resetPasswordURL)
	return s.SendEmail(to, subject, body)
}

func (s *EmailUsecase) SendVerificationEmail(to, token string) error {
	subject := "Email Verification"

	// TODO: replace this url with the link to the email verification page of your front-end app
	verificationEmailURL := fmt.Sprintf("http://link-to-app/verify-email?token=%s", token)
	body := fmt.Sprintf(`Dear user,

To verify your email, click on this link: %s

If you did not create an account, then ignore this email.`, verificationEmailURL)
	return s.SendEmail(to, subject, body)
}
