package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.kyb.sandbox/internal/domain"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/mailer"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/models"
	"github.com/invopop/gobl.kyb.sandbox/internal/domain/repos"
	"github.com/invopop/gobl.kyb.sandbox/internal/interfaces/web"
)

// mockFetcher serves a map[url]bytes, with optional per-URL errors.
// Used by the goblnet.Client the domain uses to verify incoming
// envelopes and their authority countersignatures.
type mockFetcher struct {
	data map[string][]byte
	errs map[string]error
}

func (m *mockFetcher) Fetch(_ context.Context, url string, _ http.Header) ([]byte, error) {
	if err, ok := m.errs[url]; ok {
		return nil, err
	}
	if d, ok := m.data[url]; ok {
		return d, nil
	}
	return nil, goblnet.ErrFetchFailed
}

func (m *mockFetcher) Post(_ context.Context, _ string, _ []byte, _ http.Header) error {
	return goblnet.ErrFetchFailed
}

// mockSender records send attempts. By default it succeeds; set `err`
// to make Send fail.
type mockSender struct {
	mu   sync.Mutex
	sent []sentEnvelope
	err  error
}

type sentEnvelope struct {
	to  goblnet.Address
	env *gobl.Envelope
}

func (m *mockSender) Send(_ context.Context, addr goblnet.Address, env *gobl.Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, sentEnvelope{to: addr, env: env})
	return nil
}

func (m *mockSender) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *mockSender) records() []sentEnvelope {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sentEnvelope, len(m.sent))
	copy(out, m.sent)
	return out
}

// mockMailer records messages. Set `err` to make Send fail.
type mockMailer struct {
	mu   sync.Mutex
	sent []mailer.Message
	err  error
}

func (m *mockMailer) Send(_ context.Context, msg mailer.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, msg)
	return nil
}

func (m *mockMailer) records() []mailer.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mailer.Message, len(m.sent))
	copy(out, m.sent)
	return out
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// fixture spins up a verifier identity in a tempdir + an in-memory
// store + a mock fetcher that serves the subject's and the registry's
// published keys. Returns everything the inbox and confirm tests need.
type fixture struct {
	t        *testing.T
	verifier *models.Identity
	subject  *dsig.PrivateKey
	subAddr  goblnet.Address
	registry *dsig.PrivateKey
	regAddr  goblnet.Address
	fetcher  *mockFetcher
	store    *repos.MemoryVerifications
	sender   *mockSender
	mail     *mockMailer
	setup    *domain.Setup
	mux      http.Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	verifier, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    goblnet.Address("kyb.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)

	subKey := dsig.NewES256Key()
	subPub, _ := json.Marshal(subKey.Public())
	subAddr := goblnet.Address("alice.example")

	regKey := dsig.NewES256Key()
	regPub, _ := json.Marshal(regKey.Public())
	regAddr := goblnet.Address("lookup.example")

	fetcher := &mockFetcher{
		data: map[string][]byte{
			subAddr.KeyURL(subKey.ID()): subPub,
			regAddr.KeyURL(regKey.ID()): regPub,
		},
		errs: map[string]error{},
	}
	client := goblnet.NewClient(
		goblnet.WithFetcher(fetcher),
		goblnet.WithAuthorities(regAddr),
	)
	store := repos.NewMemoryVerifications()
	send := &mockSender{}
	mail := &mockMailer{}

	setup := domain.New(domain.Deps{
		Identity:      verifier,
		Verifications: store,
		Client:        client,
		Sender:        send,
		Mailer:        mail,
		Authority:     regAddr,
		PublicBaseURL: "https://kyb.example",
		Logger:        discardLogger(),
	})
	mux := web.NewMux(setup, discardLogger())
	return &fixture{
		t: t, verifier: verifier,
		subject: subKey, subAddr: subAddr,
		registry: regKey, regAddr: regAddr,
		fetcher: fetcher, store: store, sender: send, mail: mail,
		setup: setup, mux: mux,
	}
}

// newParty builds the subject's party document with a published email.
func (f *fixture) newParty() *org.Party {
	return &org.Party{
		Name:      "Alice",
		Endpoints: []*org.Endpoint{{URI: f.subAddr.URI()}},
		Emails:    []*org.Email{{Address: "alice@example.com"}},
	}
}

// registeredEnvelope signs the party as the subject (aud = the
// registration authority) and countersigns as the registry — exactly
// the envelope a registered subject forwards to a verifier.
func (f *fixture) registeredEnvelope(party *org.Party) *gobl.Envelope {
	f.t.Helper()
	env, err := gobl.Envelop(party)
	require.NoError(f.t, err)
	require.NoError(f.t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience(f.regAddr.String())))
	f.counterSignAsRegistry(env)
	return env
}

// counterSignAsRegistry stamps the registration authority's
// countersignature onto env.
func (f *fixture) counterSignAsRegistry(env *gobl.Envelope) {
	f.t.Helper()
	require.NoError(f.t, env.Sign(f.registry,
		head.WithIssuer(f.regAddr.String()),
		head.WithAudience(f.subAddr.String()),
		head.WithExpiration(time.Now().Add(90*24*time.Hour))))
}

// waitForMail spins until the mock mailer records at least n messages
// or the deadline expires; the confirmation email is sent async.
func (f *fixture) waitForMail(n int, d time.Duration) []mailer.Message {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if got := f.mail.records(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return f.mail.records()
}

// waitForDelivery spins until the mock sender records at least n
// envelopes or the deadline expires.
func (f *fixture) waitForDelivery(n int, d time.Duration) []sentEnvelope {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if got := f.sender.records(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return f.sender.records()
}

// waitForStatus spins until the stored record reaches status s.
func (f *fixture) waitForStatus(s models.Status, d time.Duration) *models.Verification {
	f.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		rec, err := f.store.Get(context.Background(), f.subAddr)
		if err == nil && rec.Status == s {
			return rec
		}
		time.Sleep(5 * time.Millisecond)
	}
	rec, err := f.store.Get(context.Background(), f.subAddr)
	require.NoError(f.t, err)
	require.Equal(f.t, s, rec.Status, "record did not reach status %q in time", s)
	return rec
}

// confirmToken extracts the /confirm/<token> path from the recorded
// confirmation email.
func (f *fixture) confirmToken() string {
	f.t.Helper()
	msgs := f.waitForMail(1, 2*time.Second)
	require.NotEmpty(f.t, msgs, "no confirmation email recorded")
	text := msgs[len(msgs)-1].Text
	i := strings.Index(text, "https://kyb.example/confirm/")
	require.GreaterOrEqual(f.t, i, 0, "email carries no confirm link:\n%s", text)
	link := text[i:]
	if j := strings.IndexAny(link, " \t\r\n"); j >= 0 {
		link = link[:j]
	}
	u, err := url.Parse(link)
	require.NoError(f.t, err)
	return strings.TrimPrefix(u.Path, "/confirm/")
}

// bearer mints a request token from the subject for the verifier, as
// any conforming client would attach to a who or inbox request.
func (f *fixture) bearer() string {
	f.t.Helper()
	token, err := goblnet.NewToken(f.subject, f.subAddr, f.verifier.Address(), 0)
	require.NoError(f.t, err)
	return "Bearer " + token
}

func (f *fixture) post(path string, body []byte) *http.Response {
	return f.do(http.MethodPost, path, body, f.bearer(), "")
}

func (f *fixture) get(path string) *http.Response {
	return f.do(http.MethodGet, path, nil, f.bearer(), "")
}

// getConfirm performs an unauthenticated browser-style GET.
func (f *fixture) getConfirm(token string) *http.Response {
	return f.do(http.MethodGet, "/confirm/"+token, nil, "", "")
}

// postConfirm performs an unauthenticated browser-style form POST.
func (f *fixture) postConfirm(token string, form url.Values) *http.Response {
	return f.do(http.MethodPost, "/confirm/"+token, []byte(form.Encode()), "", "application/x-www-form-urlencoded")
}

// do performs a request with an explicit Authorization value; empty
// auth sends the request bare.
func (f *fixture) do(method, path string, body []byte, auth, contentType string) *http.Response {
	f.t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close() //nolint:errcheck
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(data)
}

func TestInboxAcceptsRegisteredEnvelope(t *testing.T) {
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	// Record persisted as pending with the confirmation token set.
	rec, err := f.store.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, models.StatusPending, rec.Status)
	assert.Equal(t, "alice@example.com", rec.Email)
	assert.NotEmpty(t, rec.Token)
	assert.False(t, rec.TokenExpired(time.Now()))
	assert.NotNil(t, rec.EmailSentAt, "202 means the email is already out")
	require.NotNil(t, rec.Envelope)
	assert.Len(t, rec.Envelope.Signatures, 2, "stored envelope is exactly what arrived")

	// The confirmation email went out before the 202, carrying the link.
	msgs := f.waitForMail(1, 2*time.Second)
	require.Len(t, msgs, 1)
	assert.Equal(t, "alice@example.com", msgs[0].To)
	assert.Contains(t, msgs[0].Text, "https://kyb.example/confirm/"+rec.Token)
	assert.Contains(t, msgs[0].Text, string(f.regAddr), "email names the registration authority")

	// Nothing is delivered before the attestation.
	assert.Empty(t, f.sender.records())
}

func TestInboxRejectsMissingEmail(t *testing.T) {
	f := newFixture(t)
	party := f.newParty()
	party.Emails = nil
	env := f.registeredEnvelope(party)
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	assert.Contains(t, readBody(t, resp), "email")
}

func TestInboxRejectsUnregisteredEnvelope(t *testing.T) {
	// The subject's own signature alone is not enough: the envelope
	// must carry the registration authority's countersignature.
	f := newFixture(t)
	env, err := gobl.Envelop(f.newParty())
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience(f.regAddr.String())))
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestInboxRejectsForgedRegistryCountersignature(t *testing.T) {
	f := newFixture(t)
	env, err := gobl.Envelop(f.newParty())
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience(f.regAddr.String())))
	forged := dsig.NewES256Key()
	require.NoError(t, env.Sign(forged,
		head.WithIssuer(f.regAddr.String()),
		head.WithAudience(f.subAddr.String())))
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestInboxRejectsExpiredRegistryCountersignature(t *testing.T) {
	f := newFixture(t)
	env, err := gobl.Envelop(f.newParty())
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience(f.regAddr.String())))
	require.NoError(t, env.Sign(f.registry,
		head.WithIssuer(f.regAddr.String()),
		head.WithAudience(f.subAddr.String()),
		head.WithExpiration(time.Now().Add(-time.Hour))))
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestInboxRejectsEnvelopeForAnotherAuthority(t *testing.T) {
	// The subject's signature is bound to some other registry: this
	// verifier only works for its configured authority.
	f := newFixture(t)
	env, err := gobl.Envelop(f.newParty())
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience("other-registry.example")))
	f.counterSignAsRegistry(env)
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestInboxRejectsNonPartyDocument(t *testing.T) {
	f := newFixture(t)
	msg := &org.Inbox{Code: "x"}
	env, err := gobl.Envelop(msg)
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience(f.regAddr.String())))
	f.counterSignAsRegistry(env)
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

func TestInboxRejectsUnknownSigner(t *testing.T) {
	f := newFixture(t)
	other := dsig.NewES256Key()
	party := &org.Party{
		Name:      "Mallory",
		Endpoints: []*org.Endpoint{{URI: goblnet.Address("mallory.example").URI()}},
		Emails:    []*org.Email{{Address: "mallory@example.com"}},
	}
	env, err := gobl.Envelop(party)
	require.NoError(t, err)
	require.NoError(t, env.Sign(other,
		head.WithIssuer("mallory.example"),
		head.WithAudience(f.regAddr.String())))
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestInboxRejectsOversizedBody(t *testing.T) {
	f := newFixture(t)
	resp := f.post(goblnet.InboxPath, bytes.Repeat([]byte("a"), (1<<20)+1024))
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

func TestInboxRejectsMalformedJSON(t *testing.T) {
	f := newFixture(t)
	resp := f.post(goblnet.InboxPath, []byte("not json"))
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestInboxSubjectKeyUnavailable(t *testing.T) {
	f := newFixture(t)
	f.fetcher.errs[f.subAddr.KeyURL(f.subject.ID())] = fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable)
	env := f.registeredEnvelope(f.newParty())
	body, _ := json.Marshal(env)
	// Bypass the auth middleware's key fetch by minting the token from
	// the registry (whose key stays reachable): a transient failure
	// resolving the envelope signer must answer 503, not 4xx.
	token, err := goblnet.NewToken(f.registry, f.regAddr, f.verifier.Address(), 0)
	require.NoError(t, err)
	resp := f.do(http.MethodPost, goblnet.InboxPath, body, "Bearer "+token, "")
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestInboxRegistryKeyUnavailable(t *testing.T) {
	f := newFixture(t)
	f.fetcher.errs[f.regAddr.KeyURL(f.registry.ID())] = fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable)
	env := f.registeredEnvelope(f.newParty())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestConfirmFlow(t *testing.T) {
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	token := f.confirmToken()

	// The emailed link serves the attestation form.
	page := f.getConfirm(token)
	pageBody := readBody(t, page)
	require.Equal(t, http.StatusOK, page.StatusCode)
	assert.Contains(t, pageBody, `name="accept"`)
	assert.Contains(t, pageBody, string(f.subAddr))
	assert.Equal(t, "no-store", page.Header.Get("Cache-Control"), "token is in the URL")
	assert.Equal(t, "no-referrer", page.Header.Get("Referrer-Policy"))

	// Submitting without the checkbox re-renders the form.
	miss := f.postConfirm(token, url.Values{})
	missBody := readBody(t, miss)
	assert.Equal(t, http.StatusUnprocessableEntity, miss.StatusCode)
	assert.Contains(t, missBody, `name="accept"`)

	// Submitting with the checkbox records the attestation and
	// delivers the countersigned envelope to the authority.
	ok := f.postConfirm(token, url.Values{"accept": {"on"}})
	okBody := readBody(t, ok)
	require.Equal(t, http.StatusOK, ok.StatusCode)
	assert.NotContains(t, okBody, `name="accept"`, "thank-you page carries no form")

	sent := f.waitForDelivery(1, 2*time.Second)
	require.Len(t, sent, 1)
	assert.Equal(t, f.regAddr, sent[0].to)

	// The delivered envelope: same uuid + digest, original signatures
	// intact, one fresh verifier countersignature appended.
	delivered := sent[0].env
	assert.Equal(t, env.Head.UUID, delivered.Head.UUID)
	assert.Equal(t, env.Head.Digest.Value, delivered.Head.Digest.Value)
	require.Len(t, delivered.Signatures, 3)
	p, err := head.SignedPayload(delivered.Signatures[2])
	require.NoError(t, err)
	assert.Equal(t, f.verifier.Address().String(), p.Iss)
	assert.Equal(t, f.subAddr.String(), p.Aud)
	assert.Empty(t, p.Verifier, "verifier signatures never carry the verifier claim")
	assert.Greater(t, p.ExpiresAt, time.Now().Add(364*24*time.Hour).Unix())
	assert.Less(t, p.ExpiresAt, time.Now().Add(366*24*time.Hour).Unix())

	// The stored envelope was countersigned on a copy, not in place.
	rec := f.waitForStatus(models.StatusDelivered, 2*time.Second)
	assert.Len(t, rec.Envelope.Signatures, 2, "stored envelope unchanged")
	assert.NotNil(t, rec.ConfirmedAt)
}

func TestConfirmUnknownToken(t *testing.T) {
	f := newFixture(t)
	resp := f.getConfirm("no-such-token")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, readBody(t, resp), "not valid")

	post := f.postConfirm("no-such-token", url.Values{"accept": {"on"}})
	defer post.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusNotFound, post.StatusCode)
}

func TestConfirmExpiredToken(t *testing.T) {
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())
	body, _ := json.Marshal(env)
	f.post(goblnet.InboxPath, body).Body.Close() //nolint:errcheck
	token := f.confirmToken()

	// Age the token past its TTL.
	rec, err := f.store.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	rec.TokenExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, f.store.Put(context.Background(), rec))

	resp := f.getConfirm(token)
	assert.Equal(t, http.StatusGone, resp.StatusCode)
	assert.Contains(t, readBody(t, resp), "expired")

	post := f.postConfirm(token, url.Values{"accept": {"on"}})
	defer post.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusGone, post.StatusCode)
	assert.Empty(t, f.sender.records(), "nothing is delivered on an expired link")
}

func TestConfirmIsIdempotent(t *testing.T) {
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())
	body, _ := json.Marshal(env)
	f.post(goblnet.InboxPath, body).Body.Close() //nolint:errcheck
	token := f.confirmToken()

	first := f.postConfirm(token, url.Values{"accept": {"on"}})
	first.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, first.StatusCode)
	f.waitForStatus(models.StatusDelivered, 2*time.Second)

	// A second submit (double-click, refresh) lands on the thank-you
	// page and does not deliver again.
	second := f.postConfirm(token, url.Values{"accept": {"on"}})
	secondBody := readBody(t, second)
	assert.Equal(t, http.StatusOK, second.StatusCode)
	assert.NotContains(t, secondBody, `name="accept"`)
	assert.Len(t, f.sender.records(), 1)

	// The link keeps rendering the state page too.
	again := f.getConfirm(token)
	defer again.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusOK, again.StatusCode)
}

func TestConfirmRetriesFailedDelivery(t *testing.T) {
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())
	body, _ := json.Marshal(env)
	f.post(goblnet.InboxPath, body).Body.Close() //nolint:errcheck
	token := f.confirmToken()

	// First confirmation: delivery to the authority fails. The page
	// must say so — never success for an incomplete verification —
	// while the attestation itself is durably recorded.
	f.sender.setErr(fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable))
	resp := f.postConfirm(token, url.Values{"accept": {"on"}})
	respBody := readBody(t, resp)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Contains(t, respBody, "confirmation is saved")
	assert.Contains(t, respBody, "Try again", "error page offers a retry")
	rec := f.waitForStatus(models.StatusFailed, time.Second)
	assert.NotEmpty(t, rec.LastDeliveryError)
	assert.NotNil(t, rec.ConfirmedAt)

	// Re-opening the link shows the failed state with a retry, not a
	// thank-you.
	page := f.getConfirm(token)
	pageBody := readBody(t, page)
	require.Equal(t, http.StatusOK, page.StatusCode)
	assert.Contains(t, pageBody, "Try again")
	assert.NotContains(t, pageBody, `name="accept"`, "attestation is not repeated")

	// The retry button POSTs without the checkbox and retries delivery.
	f.sender.setErr(nil)
	retry := f.postConfirm(token, url.Values{})
	retryBody := readBody(t, retry)
	require.Equal(t, http.StatusOK, retry.StatusCode)
	assert.Contains(t, retryBody, "complete")
	f.waitForStatus(models.StatusDelivered, time.Second)
	require.Len(t, f.sender.records(), 1)
}

func TestRedeliverAfterFailure(t *testing.T) {
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())
	body, _ := json.Marshal(env)
	f.post(goblnet.InboxPath, body).Body.Close() //nolint:errcheck
	token := f.confirmToken()

	f.sender.setErr(fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable))
	f.postConfirm(token, url.Values{"accept": {"on"}}).Body.Close() //nolint:errcheck
	f.waitForStatus(models.StatusFailed, 2*time.Second)

	// The redeliver command path recovers synchronously.
	f.sender.setErr(nil)
	rec, err := f.setup.Verifications().Redeliver(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, models.StatusDelivered, rec.Status)
	require.Len(t, f.sender.records(), 1)
}

func TestRedeliverRequiresConfirmation(t *testing.T) {
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())
	body, _ := json.Marshal(env)
	f.post(goblnet.InboxPath, body).Body.Close() //nolint:errcheck

	_, err := f.setup.Verifications().Redeliver(context.Background(), f.subAddr)
	require.ErrorIs(t, err, domain.ErrValidation)

	_, err = f.setup.Verifications().Redeliver(context.Background(), "nobody.example")
	require.ErrorIs(t, err, domain.ErrNotFound)
}

func TestRenewalAfterConfirmationSkipsEmail(t *testing.T) {
	f := newFixture(t)
	party := f.newParty()
	env1 := f.registeredEnvelope(party) // envelop assigns the party's UUID
	body1, _ := json.Marshal(env1)
	f.post(goblnet.InboxPath, body1).Body.Close() //nolint:errcheck
	token := f.confirmToken()
	f.postConfirm(token, url.Values{"accept": {"on"}}).Body.Close() //nolint:errcheck
	f.waitForStatus(models.StatusDelivered, 2*time.Second)

	// The registry re-registers the unchanged party (same digest) and
	// the subject forwards it again: the recorded attestation binds to
	// the digest, so no second email — straight to delivery.
	env2 := f.registeredEnvelope(party)
	require.Equal(t, env1.Head.Digest.Value, env2.Head.Digest.Value, "unchanged party renews with the same digest")
	body2, _ := json.Marshal(env2)
	resp := f.post(goblnet.InboxPath, body2)
	resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	sent := f.waitForDelivery(2, 2*time.Second)
	require.Len(t, sent, 2, "renewal delivers without a new attestation")
	assert.Len(t, f.mail.records(), 1, "no second confirmation email")
}

func TestChangedPartyRestartsAttestation(t *testing.T) {
	f := newFixture(t)
	env1 := f.registeredEnvelope(f.newParty())
	body1, _ := json.Marshal(env1)
	f.post(goblnet.InboxPath, body1).Body.Close() //nolint:errcheck
	token1 := f.confirmToken()
	f.postConfirm(token1, url.Values{"accept": {"on"}}).Body.Close() //nolint:errcheck
	f.waitForStatus(models.StatusDelivered, 2*time.Second)

	// Changed party data: the prior attestation no longer applies.
	party := f.newParty()
	party.Name = "Alice Ltd"
	env2 := f.registeredEnvelope(party)
	body2, _ := json.Marshal(env2)
	f.post(goblnet.InboxPath, body2).Body.Close() //nolint:errcheck

	rec, err := f.store.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, models.StatusPending, rec.Status)
	assert.Nil(t, rec.ConfirmedAt)
	assert.NotEqual(t, token1, rec.Token, "fresh link for the new digest")
	require.Len(t, f.waitForMail(2, 2*time.Second), 2, "second confirmation email sent")
	assert.Len(t, f.sender.records(), 1, "no delivery until the new attestation")

	// The old link is dead; the new one works.
	old := f.getConfirm(token1)
	defer old.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusNotFound, old.StatusCode)
}

func TestEmailFailureFailsRequest(t *testing.T) {
	f := newFixture(t)
	f.mail.err = fmt.Errorf("smtp: connection refused")
	env := f.registeredEnvelope(f.newParty())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"an unsent confirmation email must surface to the sender, not vanish behind a 202")
	assert.Contains(t, readBody(t, resp), "confirmation email")

	// The failure is on the record: pending, error noted, nothing sent.
	rec, err := f.store.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, models.StatusPending, rec.Status)
	assert.NotEmpty(t, rec.LastEmailError)
	assert.Nil(t, rec.EmailSentAt)

	// The sender retries the same envelope once the mailer recovers:
	// a fresh link goes out and the request is acknowledged.
	f.mail.err = nil
	retry := f.post(goblnet.InboxPath, body)
	defer retry.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusAccepted, retry.StatusCode)
	rec, err = f.store.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.NotNil(t, rec.EmailSentAt)
	assert.Empty(t, rec.LastEmailError)
	require.Len(t, f.mail.records(), 1)
}

func TestRenewalDeliveryFailureFailsRequest(t *testing.T) {
	f := newFixture(t)
	party := f.newParty()
	env1 := f.registeredEnvelope(party)
	body1, _ := json.Marshal(env1)
	f.post(goblnet.InboxPath, body1).Body.Close() //nolint:errcheck
	f.postConfirm(f.confirmToken(), url.Values{"accept": {"on"}}).Body.Close() //nolint:errcheck
	f.waitForStatus(models.StatusDelivered, 2*time.Second)

	// A renewal skips the email and delivers synchronously: a failed
	// delivery to the registry fails the request so the sender retries.
	f.sender.setErr(fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable))
	env2 := f.registeredEnvelope(party)
	body2, _ := json.Marshal(env2)
	resp := f.post(goblnet.InboxPath, body2)
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Contains(t, readBody(t, resp), "registration authority")

	f.sender.setErr(nil)
	retry := f.post(goblnet.InboxPath, body2)
	defer retry.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusAccepted, retry.StatusCode)
	rec, err := f.store.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, models.StatusDelivered, rec.Status)
}

func TestWhoGet(t *testing.T) {
	f := newFixture(t)
	resp := f.get(goblnet.WhoPath)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got gobl.Envelope
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got.Signatures, 1)
	p, err := head.SignedPayload(got.Signatures[0])
	require.NoError(t, err)
	assert.Equal(t, f.verifier.Address().String(), p.Iss)
	assert.Empty(t, p.Aud, "GET who response is not bound to a caller")
}

func TestKeysEndpoint(t *testing.T) {
	f := newFixture(t)
	kid := f.verifier.PrivateKey.ID()
	resp := f.get(goblnet.KeyPath(kid))
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var pk dsig.PublicKey
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pk))
	assert.Equal(t, kid, pk.ID())
}

func TestJWKSEndpoint(t *testing.T) {
	f := newFixture(t)
	resp := f.get(goblnet.JWKSPath)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))
	require.Len(t, set.Keys, 1)
}

func TestHealth(t *testing.T) {
	f := newFixture(t)
	resp := f.get("/healthz")
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRequestAuth(t *testing.T) {
	f := newFixture(t)

	t.Run("who without a token is rejected", func(t *testing.T) {
		resp := f.do(http.MethodGet, goblnet.WhoPath, nil, "", "")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("inbox without a token is rejected", func(t *testing.T) {
		env := f.registeredEnvelope(f.newParty())
		body, _ := json.Marshal(env)
		resp := f.do(http.MethodPost, goblnet.InboxPath, body, "", "")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("token bound to another audience is rejected", func(t *testing.T) {
		token, err := goblnet.NewToken(f.subject, f.subAddr, "other.example", 0)
		require.NoError(t, err)
		resp := f.do(http.MethodGet, goblnet.WhoPath, nil, "Bearer "+token, "")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("requester key unavailability answers 503", func(t *testing.T) {
		f2 := newFixture(t)
		f2.fetcher.errs[f2.subAddr.KeyURL(f2.subject.ID())] = fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable)
		resp := f2.get(goblnet.WhoPath)
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("keys and confirm stay open", func(t *testing.T) {
		resp := f.do(http.MethodGet, goblnet.KeyPath(f.verifier.PrivateKey.ID()), nil, "", "")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		page := f.getConfirm("missing")
		defer page.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusNotFound, page.StatusCode, "reachable without a token — 404, not 401")
	})
}

func TestInboxAcceptsOwnCountersignatureAboard(t *testing.T) {
	// A subject may re-submit the fully endorsed envelope (our own
	// earlier countersignature included) — e.g. republishing after the
	// registry round trip. Our genuine signature aboard is fine.
	f := newFixture(t)
	party := f.newParty()
	env := f.registeredEnvelope(party)
	require.NoError(t, env.Sign(f.verifier.PrivateKey,
		head.WithIssuer(f.verifier.Address().String()),
		head.WithAudience(f.subAddr.String()),
		head.WithExpiration(time.Now().Add(365*24*time.Hour))))

	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

func TestInboxRejectsForgedOwnCountersignature(t *testing.T) {
	// A signature claiming this verifier's address but made with a
	// different key: the envelope is not the one we attested to.
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())
	forged := dsig.NewES256Key()
	require.NoError(t, env.Sign(forged,
		head.WithIssuer(f.verifier.Address().String()),
		head.WithAudience(f.subAddr.String())))

	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestInboxAcceptsPublicationFirstSignature(t *testing.T) {
	// A subject signing publication-first (no audience) with the
	// registration signature appended binds through the search, not
	// the first signature's audience.
	f := newFixture(t)
	party := f.newParty()
	env, err := gobl.Envelop(party)
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject, head.WithIssuer(f.subAddr.String())))
	require.NoError(t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience(f.regAddr.String())))
	f.counterSignAsRegistry(env)

	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}
