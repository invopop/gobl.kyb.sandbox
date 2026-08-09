package domain

import (
	"strings"
	"text/template"

	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"

	"github.com/invopop/gobl.kyb.sandbox/internal/domain/mailer"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/models"
)

// confirmationText is the body of the confirmation email. Plain text
// only: the message's job is to carry the link, and text survives
// every client and spam filter posture.
var confirmationText = template.Must(template.New("confirmation").Parse(
	`Hello{{if .Name}} {{.Name}}{{end}},

A verification of the GOBL Net identity "{{.Address}}" was requested
through the registration authority {{.Authority}}.

To complete it, open the link below and accept the declaration that
you are legally entitled to use the identity and credentials being
registered:

  {{.ConfirmURL}}

The link expires on {{.Expires}}. If you did not request this
verification, ignore this message and nothing will change.

This is a sandbox verification service ({{.Verifier}}): it confirms
control of this email address and records your declaration, nothing
more.
`))

// confirmationMessage builds the confirmation email for a pending
// verification record.
func confirmationMessage(rec *models.Verification, verifier, authority goblnet.Address, publicBaseURL string) mailer.Message {
	name := ""
	if rec.Envelope != nil {
		if party, ok := rec.Envelope.Extract().(*org.Party); ok {
			name = party.Name
		}
	}
	var b strings.Builder
	_ = confirmationText.Execute(&b, map[string]string{
		"Name":       name,
		"Address":    string(rec.Address),
		"Authority":  string(authority),
		"Verifier":   string(verifier),
		"ConfirmURL": publicBaseURL + "/confirm/" + rec.Token,
		"Expires":    rec.TokenExpiresAt.UTC().Format("2 January 2006 15:04 MST"),
	})
	return mailer.Message{
		To:      rec.Email,
		ToName:  name,
		Subject: "Verify the GOBL Net identity " + string(rec.Address),
		Text:    b.String(),
	}
}
