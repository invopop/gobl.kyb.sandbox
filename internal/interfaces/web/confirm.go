package web

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/invopop/gobl.kyb.sandbox/internal/domain"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/models"
)

// confirmPage is the single template behind the human-facing /confirm
// pages: the attestation form, the thank-you states, and the error
// states. One page, no assets — the emailed link must work in any
// browser without further requests.
var confirmPage = template.Must(template.New("confirm").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}} — GOBL Sandbox KYB</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; background: #f5f5f4; color: #1c1917; }
  main { max-width: 34rem; margin: 4rem auto; padding: 2rem; background: #fff;
         border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  h1 { font-size: 1.25rem; margin-top: 0; }
  code { background: #f5f5f4; padding: 0.1rem 0.3rem; border-radius: 0.25rem; }
  label { display: flex; gap: 0.6rem; align-items: flex-start; margin: 1.5rem 0; }
  input[type=checkbox] { margin-top: 0.25rem; }
  button { background: #1c1917; color: #fff; border: 0; border-radius: 0.375rem;
           padding: 0.6rem 1.2rem; font-size: 1rem; cursor: pointer; }
  .error { color: #b91c1c; }
  .note { color: #57534e; font-size: 0.875rem; }
</style>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Message}}<p>{{.Message}}</p>{{end}}
{{if .ShowForm}}
<p>A verification of the GOBL Net identity <code>{{.Address}}</code>
was requested through the registration authority
<code>{{.Authority}}</code>.</p>
<form method="post">
  <label>
    <input type="checkbox" name="accept" value="on">
    <span>I confirm that I am legally entitled to use the identity and
    credentials being registered for <code>{{.Address}}</code>, and I
    understand this is a sandbox environment.</span>
  </label>
  <button type="submit">Confirm verification</button>
</form>
{{end}}
{{if .ShowRetry}}
<form method="post">
  <button type="submit">Try again</button>
</form>
{{end}}
<p class="note">This sandbox service verifies control of the published
email address and records the declaration above — nothing more.</p>
</main>
</body>
</html>
`))

// confirmView is the data handed to the confirm template.
type confirmView struct {
	Title     string
	Address   string
	Authority string
	Message   string
	Error     string
	ShowForm  bool
	ShowRetry bool
}

// renderConfirm writes a confirm page. The emailed token is in the
// URL, so the responses must never land in shared caches or leak via
// referrers.
func renderConfirm(w http.ResponseWriter, status int, view confirmView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_ = confirmPage.Execute(w, view)
}

// confirmErrorView maps a domain error from the token lookup onto the
// page shown to the human behind the link.
func confirmErrorView(err error) (int, confirmView) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound, confirmView{
			Title: "Link not recognized",
			Error: "This confirmation link is not valid. Check that the full link from the email was used.",
		}
	case errors.Is(err, domain.ErrGone):
		return http.StatusGone, confirmView{
			Title: "Link expired",
			Error: "This confirmation link has expired. Register the identity again to receive a fresh one.",
		}
	case errors.Is(err, domain.ErrUnavailable):
		msg := "The verification could not be processed right now. Try again in a few minutes."
		var de *domain.Error
		if errors.As(err, &de) && de.Message() != "" {
			msg = de.Message()
		}
		return http.StatusServiceUnavailable, confirmView{
			Title:     "Temporarily unavailable",
			Error:     msg,
			ShowRetry: true,
		}
	default:
		return http.StatusInternalServerError, confirmView{
			Title: "Something went wrong",
			Error: "The verification could not be processed. Try the link again later.",
		}
	}
}

// resultView renders the state of a record that no longer needs the
// form: attestation recorded, delivery pending / done / failed.
func resultView(s *domain.Setup, rec *models.Verification) confirmView {
	view := confirmView{
		Title:     "Verification confirmed",
		Address:   string(rec.Address),
		Authority: string(s.Verifications().Authority()),
	}
	switch rec.Status {
	case models.StatusDelivered:
		view.Message = "The verification is complete and has been delivered to the registration authority. The registry will return the updated registration to your service shortly."
	case models.StatusFailed:
		view.Title = "Delivery failed"
		view.Error = "Your confirmation is saved, but delivering the result to the registration authority failed. Try again now, or come back to this link later."
		view.ShowRetry = true
	default:
		view.Message = "Your confirmation is recorded and the result is being delivered to the registration authority."
		view.ShowRetry = true
	}
	return view
}

// handleConfirmPage serves the attestation form behind the emailed
// link, or the current state when the attestation is already recorded.
func handleConfirmPage(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, err := s.Verifications().Confirmation(r.Context(), r.PathValue("token"))
		if err != nil {
			status, view := confirmErrorView(err)
			renderConfirm(w, status, view)
			return
		}
		if rec.Status != models.StatusPending {
			renderConfirm(w, http.StatusOK, resultView(s, rec))
			return
		}
		renderConfirm(w, http.StatusOK, confirmView{
			Title:     "Verify your GOBL Net identity",
			Address:   string(rec.Address),
			Authority: string(s.Verifications().Authority()),
			ShowForm:  true,
		})
	}
}

// handleConfirmSubmit records the attestation and delivers the
// result. The checkbox gates only the first attestation — once it is
// recorded, a POST is the retry button and goes straight to Confirm,
// which re-attempts an undelivered outcome. Delivery failures render
// as errors with a retry so the subject never sees success for a
// verification that did not complete.
func handleConfirmSubmit(s *domain.Setup, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		rec, err := s.Verifications().Confirmation(r.Context(), token)
		if err != nil {
			status, view := confirmErrorView(err)
			renderConfirm(w, status, view)
			return
		}
		if rec.Status == models.StatusPending {
			if perr := r.ParseForm(); perr != nil || r.PostForm.Get("accept") != "on" {
				renderConfirm(w, http.StatusUnprocessableEntity, confirmView{
					Title:     "Verify your GOBL Net identity",
					Address:   string(rec.Address),
					Authority: string(s.Verifications().Authority()),
					Error:     "Tick the declaration box to confirm the verification.",
					ShowForm:  true,
				})
				return
			}
		}
		rec, err = s.Verifications().Confirm(r.Context(), token)
		if err != nil {
			status, view := confirmErrorView(err)
			renderConfirm(w, status, view)
			return
		}
		log.Info("confirm.submitted", "address", string(rec.Address))
		renderConfirm(w, http.StatusOK, resultView(s, rec))
	}
}
