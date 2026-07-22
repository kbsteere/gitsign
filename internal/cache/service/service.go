// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/gitsign/internal/oidc"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type Service struct {
	store *cache.Cache

	// refreshMu guards refreshTokens. It also serializes refresh grants:
	// providers such as Dex rotate refresh tokens on every use and reject
	// reuse, so concurrent refreshes with the same token would invalidate
	// the session.
	refreshMu sync.Mutex
	// refreshTokens holds OIDC refresh tokens in memory only, keyed by
	// issuer and client ID. They are never persisted to disk.
	refreshTokens map[string]refreshToken

	// authorize, refresh, mint, interactive, and now are overridable for testing.
	authorize   func(ctx context.Context, cfg *config.Config) (*oidc.Tokens, error)
	refresh     func(ctx context.Context, cfg *config.Config, refreshToken string) (*oidc.Tokens, error)
	mint        func(ctx context.Context, cfg *config.Config, idToken string) (*fulcio.Identity, error)
	interactive func(ctx context.Context, cfg *config.Config) (*fulcio.Identity, error)
	now         func() time.Time
}

// refreshToken pairs a refresh token with the time of the interactive login
// that produced it. Token rotation preserves issuedAt, so the session age is
// always measured from the login, not the last use.
type refreshToken struct {
	token    string
	issuedAt time.Time
}

const (
	defaultExpiration = 10 * time.Minute
	cleanupInterval   = 1 * time.Minute
)

var errNoRefreshToken = errors.New("no refresh token stored")

func NewService() *Service {
	s := &Service{
		store:         cache.New(defaultExpiration, cleanupInterval),
		refreshTokens: map[string]refreshToken{},
		now:           time.Now,
		authorize: func(ctx context.Context, cfg *config.Config) (*oidc.Tokens, error) {
			flow, err := oidc.NewFlow(cfg, os.Stdin, os.Stdout)
			if err != nil {
				return nil, err
			}
			return flow.Authorize(ctx)
		},
		refresh: func(ctx context.Context, cfg *config.Config, refreshToken string) (*oidc.Tokens, error) {
			clientSecret, err := cfg.ClientSecret()
			if err != nil {
				return nil, err
			}
			return oidc.Refresh(ctx, cfg.Issuer, cfg.ClientID, clientSecret, refreshToken)
		},
		mint: func(ctx context.Context, cfg *config.Config, idToken string) (*fulcio.Identity, error) {
			return fulcio.NewIdentityFactory(os.Stdin, os.Stdout).NewIdentityWithToken(ctx, cfg, idToken)
		},
		interactive: func(ctx context.Context, cfg *config.Config) (*fulcio.Identity, error) {
			return fulcio.NewIdentityFactory(os.Stdin, os.Stdout).NewIdentity(ctx, cfg)
		},
	}
	return s
}

func (s *Service) StoreCredential(req api.StoreCredentialRequest, resp *api.Credential) error {
	fmt.Println("Store", req.ID)
	if err := s.store.Add(req.ID, req.Credential, 10*time.Minute); err != nil {
		return err
	}
	*resp = *req.Credential
	return nil
}

func (s *Service) GetCredential(req api.GetCredentialRequest, resp *api.Credential) error {
	ctx := context.Background()
	fmt.Println("Get", req.ID)
	i, ok := s.store.Get(req.ID)
	if ok {
		fmt.Println("gitsign-credential-cache: found credential!")
		cred, ok := i.(*api.Credential)
		if !ok {
			return fmt.Errorf("unknown credential type %T", i)
		}
		*resp = *cred
		return nil
	}

	if req.Config == nil {
		// No config set, nothing to do.
		return fmt.Errorf("%q not found", req.ID)
	}

	cred, err := s.newCredential(ctx, req.Config)
	if err != nil {
		return err
	}

	if err := s.store.Add(req.ID, cred, 10*time.Minute); err != nil {
		// We still generated the credential just fine, so only log the error.
		fmt.Printf("error storing credential: %v\n", err)
	}
	*resp = *cred
	return nil
}

// newCredential gets a new credential using the flow selected by the config.
func (s *Service) newCredential(ctx context.Context, cfg *config.Config) (*api.Credential, error) {
	if cfg.OfflineAccess {
		return s.offlineAccessCredential(ctx, cfg)
	}

	// If nothing is in the cache, fallback to interactive flow.
	fmt.Println("gitsign-credential-cache: no cached credential found, falling back to interactive flow...")
	id, err := s.interactive(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error getting new identity: %w", err)
	}
	return credential(id)
}

// offlineAccessCredential gets a new credential using a stored refresh token
// when one is available, and falls back to the interactive flow (storing the
// resulting refresh token for next time) when it is not.
func (s *Service) offlineAccessCredential(ctx context.Context, cfg *config.Config) (*api.Credential, error) {
	cred, err := s.refreshCredential(ctx, cfg)
	if err == nil {
		fmt.Println("gitsign-credential-cache: minted credential from refresh token")
		return cred, nil
	}
	if !errors.Is(err, errNoRefreshToken) {
		fmt.Printf("gitsign-credential-cache: error refreshing credential: %v\n", err)
	}

	fmt.Println("gitsign-credential-cache: no cached credential found, falling back to interactive flow...")
	tokens, err := s.authorize(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error running interactive flow: %w", err)
	}
	s.setRefreshToken(cfg, tokens.RefreshToken)
	id, err := s.mint(ctx, cfg, tokens.IDToken)
	if err != nil {
		return nil, fmt.Errorf("error getting new identity: %w", err)
	}
	return credential(id)
}

// refreshCredential mints a new credential from the stored refresh token,
// storing the rotated refresh token that replaces it. A refresh token that
// fails is dropped so the next attempt goes through the interactive flow
// rather than retrying a dead token.
func (s *Service) refreshCredential(ctx context.Context, cfg *config.Config) (*api.Credential, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	rt, ok := s.refreshTokens[refreshKey(cfg)]
	if !ok {
		return nil, errNoRefreshToken
	}
	if cfg.OfflineAccessMaxAge > 0 && s.now().Sub(rt.issuedAt) > cfg.OfflineAccessMaxAge {
		delete(s.refreshTokens, refreshKey(cfg))
		return nil, fmt.Errorf("refresh token is older than %v, requiring a new interactive login", cfg.OfflineAccessMaxAge)
	}
	tokens, err := s.refresh(ctx, cfg, rt.token)
	if err != nil {
		delete(s.refreshTokens, refreshKey(cfg))
		return nil, err
	}
	s.refreshTokens[refreshKey(cfg)] = refreshToken{token: tokens.RefreshToken, issuedAt: rt.issuedAt}

	id, err := s.mint(ctx, cfg, tokens.IDToken)
	if err != nil {
		return nil, err
	}
	return credential(id)
}

func (s *Service) setRefreshToken(cfg *config.Config, token string) {
	if token == "" {
		return
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	s.refreshTokens[refreshKey(cfg)] = refreshToken{token: token, issuedAt: s.now()}
}

// refreshKey identifies the OIDC session a refresh token belongs to. Unlike
// credential IDs, refresh tokens are not scoped to a working directory, so
// one interactive login covers every repo using the same issuer and client.
func refreshKey(cfg *config.Config) string {
	return cfg.Issuer + "|" + cfg.ClientID
}

func credential(id *fulcio.Identity) (*api.Credential, error) {
	privPEM, err := cryptoutils.MarshalPrivateKeyToPEM(id.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &api.Credential{
		PrivateKey: privPEM,
		Cert:       id.CertPEM,
		Chain:      id.ChainPEM,
	}, nil
}
