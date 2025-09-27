package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jnschaeffer/passkey-demo/internal/storage"
	"github.com/jnschaeffer/passkey-demo/internal/types"
)

const sessionCookieName = "ws"

type serviceConfig struct {
	rpDisplayName        string
	rpID                 string
	rpOrigins            []string
	conveyancePreference protocol.ConveyancePreference
	storage              *storage.Service
}

// Option represents a configuration option for a WebAuthn service.
type Option func(*serviceConfig)

// WithRPDisplay name sets the display name for the Relying Party.
func WithRPDisplayName(name string) Option {
	return func(cfg *serviceConfig) {
		cfg.rpDisplayName = name
	}
}

// WithRPID sets the ID for the Relying Party. This should be the domain name from which the WebAuthn service is served.
func WithRPID(id string) Option {
	return func(cfg *serviceConfig) {
		cfg.rpID = id
	}
}

// WithRPOrigins sets the allowed origins for the Relying Party.
func WithRPOrigins(origins []string) Option {
	return func(cfg *serviceConfig) {
		cfg.rpOrigins = origins
	}
}

// WithStorage sets the storage backend for the WebAuthn service. This option is required.
func WithStorage(svc *storage.Service) Option {
	return func(cfg *serviceConfig) {
		cfg.storage = svc
	}
}

// WithConveyancePreference sets the attestation conveyance preference for authenticators.
func WithConveyancePreference(pref protocol.ConveyancePreference) Option {
	return func(cfg *serviceConfig) {
		cfg.conveyancePreference = pref
	}
}

type loginResponse struct {
	Username string `json:"username"`
}

// Service represents a WebAuthn Relying Party service.
type Service struct {
	w       *webauthn.WebAuthn
	storage *storage.Service
}

// NewService creates a new Service with the given options.
func NewService(opts ...Option) (*Service, error) {
	var (
		err   error
		cfg   serviceConfig
		wauth *webauthn.WebAuthn
	)

	for _, opt := range opts {
		opt(&cfg)
	}

	config := webauthn.Config{
		RPDisplayName:         cfg.rpDisplayName,
		RPID:                  cfg.rpID,
		RPOrigins:             cfg.rpOrigins,
		AttestationPreference: cfg.conveyancePreference,
	}

	if wauth, err = webauthn.New(&config); err != nil {
		return nil, err
	}

	svc := Service{
		w:       wauth,
		storage: cfg.storage,
	}

	return &svc, nil
}

// HandleRegistrationBegin handles HTTP requests to begin a WebAuthn registration ceremony.
func (s *Service) HandleRegistrationBegin(rw http.ResponseWriter, r *http.Request) {
	var (
		err         error
		creation    *protocol.CredentialCreation
		sessionData *webauthn.SessionData
		session     types.Session
		user        types.User
	)

	username := r.PathValue("username")

	if user, err = s.storage.CreateUser(username); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	opts := []webauthn.RegistrationOption{
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	}

	if creation, sessionData, err = s.w.BeginRegistration(&user, opts...); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if session, err = s.storage.CreateSession(sessionData); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	sessionID := base64.StdEncoding.EncodeToString(session.ID[:])

	cookie := http.Cookie{
		Name:    sessionCookieName,
		Value:   sessionID,
		Expires: session.WebAuthn.Expires,
		Path:    "/",
	}

	http.SetCookie(rw, &cookie)

	encoder := json.NewEncoder(rw)

	if err = encoder.Encode(creation); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// HandleRegistrationFinish handles HTTP requests to finish a WebAuthn registration ceremony.
func (s *Service) HandleRegistrationFinish(rw http.ResponseWriter, r *http.Request) {
	var (
		err           error
		session       types.Session
		user          types.User
		sessionCookie *http.Cookie
		sessionID     types.ID
		credential    *webauthn.Credential
	)

	username := r.PathValue("username")

	if user, err = s.storage.GetUserByName(username); err != nil {
		log.Printf("error getting user: %s", err)
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	if sessionCookie, err = r.Cookie(sessionCookieName); err != nil {
		log.Printf("error getting cookie: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if sessionID, err = types.DecodeID(sessionCookie.Value); err != nil {
		log.Printf("error decoding cookie: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if session, err = s.storage.GetSession(sessionID); err != nil {
		log.Printf("error getting session: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if credential, err = s.w.FinishRegistration(&user, session.WebAuthn, r); err != nil {
		log.Printf("error finishing registration: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err = s.storage.CreateCredential(user.ID, credential); err != nil {
		log.Printf("error creating credential: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
}

// HandleAuthenticationBegin handles HTTP requests to begin a WebAuthn authentication ceremony.
func (s *Service) HandleAuthenticationBegin(rw http.ResponseWriter, r *http.Request) {
	var (
		err         error
		assertion   *protocol.CredentialAssertion
		sessionData *webauthn.SessionData
		session     types.Session
	)

	if assertion, sessionData, err = s.w.BeginDiscoverableLogin(); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if session, err = s.storage.CreateSession(sessionData); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	sessionID := base64.StdEncoding.EncodeToString(session.ID[:])

	cookie := http.Cookie{
		Name:    sessionCookieName,
		Value:   sessionID,
		Expires: session.WebAuthn.Expires,
		Path:    "/",
	}

	http.SetCookie(rw, &cookie)

	encoder := json.NewEncoder(rw)

	encoder.Encode(assertion)
}

// HandleAuthenticationFinish handles HTTP requests to finish a WebAuthn authentication ceremony.
func (s *Service) HandleAuthenticationFinish(rw http.ResponseWriter, r *http.Request) {
	var (
		err           error
		sessionCookie *http.Cookie
		sessionID     types.ID
		session       types.Session
		user          webauthn.User
	)

	if sessionCookie, err = r.Cookie(sessionCookieName); err != nil {
		log.Printf("error getting cookie: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if sessionID, err = types.DecodeID(sessionCookie.Value); err != nil {
		log.Printf("error decoding cookie: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if session, err = s.storage.GetSession(sessionID); err != nil {
		log.Printf("error getting session: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if user, _, err = s.w.FinishPasskeyLogin(s.storage.DiscoverCredential, session.WebAuthn, r); err != nil {
		log.Printf("error finishing login: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := loginResponse{
		Username: user.WebAuthnDisplayName(),
	}

	encoder := json.NewEncoder(rw)

	if err = encoder.Encode(&response); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
}
