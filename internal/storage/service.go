package storage

import (
	"encoding/base64"
	"errors"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jnschaeffer/passkey-demo/internal/types"
)

type Service struct{
	sessions map[types.ID]types.Session
	usersByName map[string]types.ID
	usersByID map[types.ID]types.User
	credentials map[types.ID]map[string]types.Credential
}

func NewService() *Service {
	sessionMap := make(map[types.ID]types.Session)
	usersByNameMap := make(map[string]types.ID)
	usersByIDMap := make(map[types.ID]types.User)
	credentialsMap := make(map[types.ID]map[string]types.Credential)

	out := Service{
		sessions: sessionMap,
		usersByName: usersByNameMap,
		usersByID: usersByIDMap,
		credentials: credentialsMap,
	}

	return &out
}

func (s *Service) CreateSession(data *webauthn.SessionData) (types.Session, error) {
	var (
		id types.ID
		err error
	)
	
	if id, err = types.NewID(); err != nil {
		return types.Session{}, err
	}

	out := types.Session{
		ID: id,
		WebAuthn: *data,
	}

	s.sessions[id] = out

	return out, nil
}

func (s *Service) GetSession(sessionID types.ID) (types.Session, error) {
	session, ok := s.sessions[sessionID]

	if !ok {
		return types.Session{}, errors.New("not found")
	}

	return session, nil
}

func (s *Service) CreateUser(name string) (types.User, error) {
	var (
		id types.ID
		err error
	)

	if id, err = types.NewID(); err != nil {
		return types.User{}, err
	}

	out := types.User{
		ID: id,
		Name: name,
	}

	s.usersByName[name] = id
	s.usersByID[id] = out

	return out, nil
}

func (s *Service) GetUserByName(name string) (types.User, error) {
	id, ok := s.usersByName[name]

	if !ok {
		return types.User{}, errors.New("not found")
	}

	user, ok := s.usersByID[id]

	if !ok {
		return types.User{}, errors.New("not found")
	}

	return user, nil
}

func (s *Service) GetUserByID(id types.ID) (types.User, error) {
	user, ok := s.usersByID[id]

	if !ok {
		return types.User{}, errors.New("not found")
	}

	credentials := make([]types.Credential, len(s.credentials[id]))

	for _, c := range s.credentials[id] {
		credentials = append(credentials, c)
	}

	user.Credentials = credentials

	return user, nil
}

func (s *Service) CreateCredential(userID types.ID, credential *webauthn.Credential) (types.Credential, error) {
	var (
		credentials map[string]types.Credential
		ok bool
	)

	credentialID := base64.StdEncoding.EncodeToString(credential.ID)
	
	out := types.Credential{
		WebAuthn: *credential,
	}

	if credentials, ok = s.credentials[userID]; !ok {
		credentials = make(map[string]types.Credential)
		s.credentials[userID] = credentials
	}

	credentials[credentialID] = out

	return out, nil
}

func (s *Service) DiscoverCredential(rawCredID, rawUserID []byte) (webauthn.User, error) {
	var (
		userID types.ID
		err error
		credentials map[string]types.Credential
		ok bool
		user types.User
	)

	if userID, err = types.NewIDFromBytes(rawUserID); err != nil {
		return &types.User{}, err
	}

	if credentials, ok = s.credentials[userID]; !ok {
		return &types.User{}, errors.New("user not found")
	}

	credentialID := base64.StdEncoding.EncodeToString(rawCredID)
		
	if _, ok = credentials[credentialID]; !ok {
		return &types.User{}, errors.New("credential not found")
	}

	if user, err = s.GetUserByID(userID); err != nil {
		return &types.User{}, err
	}

	return &user, nil
}
