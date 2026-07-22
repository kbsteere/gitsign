// Copyright 2026 The Sigstore Authors
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/gitsign/internal/oidc"
)

// fakeFlows wires a Service with fake authorize/refresh/mint implementations
// that mimic provider refresh token rotation, and counts calls to each.
type fakeFlows struct {
	authorizeCalls int
	refreshCalls   int
	liveToken      string
	refreshErr     error
}

func newTestService(t *testing.T, f *fakeFlows) *Service {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s := NewService()
	s.authorize = func(_ context.Context, _ *config.Config) (*oidc.Tokens, error) {
		f.authorizeCalls++
		f.liveToken = fmt.Sprintf("authorize-rt-%d", f.authorizeCalls)
		return &oidc.Tokens{IDToken: "id-token", RefreshToken: f.liveToken}, nil
	}
	s.refresh = func(_ context.Context, _ *config.Config, refreshToken string) (*oidc.Tokens, error) {
		f.refreshCalls++
		if f.refreshErr != nil {
			return nil, f.refreshErr
		}
		if refreshToken != f.liveToken {
			return nil, fmt.Errorf("refresh token %q is invalid or has already been claimed", refreshToken)
		}
		f.liveToken = fmt.Sprintf("refresh-rt-%d", f.refreshCalls)
		return &oidc.Tokens{IDToken: "id-token", RefreshToken: f.liveToken}, nil
	}
	s.mint = func(_ context.Context, _ *config.Config, _ string) (*fulcio.Identity, error) {
		return &fulcio.Identity{
			PrivateKey: priv,
			CertPEM:    []byte("cert"),
			ChainPEM:   []byte("chain"),
		}, nil
	}
	s.interactive = func(_ context.Context, _ *config.Config) (*fulcio.Identity, error) {
		return nil, errors.New("interactive flow not available in tests")
	}
	return s
}

func TestOfflineAccess(t *testing.T) {
	f := &fakeFlows{}
	s := newTestService(t, f)
	cfg := &config.Config{
		Issuer:        "https://example.com/auth",
		ClientID:      "sigstore",
		OfflineAccess: true,
	}

	// First request has no refresh token, so the interactive flow runs and
	// its refresh token is kept.
	if err := s.GetCredential(api.GetCredentialRequest{ID: "repo-a", Config: cfg}, new(api.Credential)); err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if f.authorizeCalls != 1 || f.refreshCalls != 0 {
		t.Fatalf("flow calls: got = %d authorize / %d refresh, want = 1 / 0", f.authorizeCalls, f.refreshCalls)
	}
	if got := s.refreshTokens[refreshKey(cfg)]; got != "authorize-rt-1" {
		t.Fatalf("stored refresh token: got = %q, want = %q", got, "authorize-rt-1")
	}

	// A different credential ID misses the cache but reuses the refresh
	// token instead of prompting again, storing the rotated token.
	if err := s.GetCredential(api.GetCredentialRequest{ID: "repo-b", Config: cfg}, new(api.Credential)); err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if f.authorizeCalls != 1 || f.refreshCalls != 1 {
		t.Fatalf("flow calls: got = %d authorize / %d refresh, want = 1 / 1", f.authorizeCalls, f.refreshCalls)
	}
	if got := s.refreshTokens[refreshKey(cfg)]; got != "refresh-rt-1" {
		t.Fatalf("stored refresh token: got = %q, want = %q", got, "refresh-rt-1")
	}

	// Same ID hits the credential cache without touching any flow.
	if err := s.GetCredential(api.GetCredentialRequest{ID: "repo-b", Config: cfg}, new(api.Credential)); err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if f.authorizeCalls != 1 || f.refreshCalls != 1 {
		t.Fatalf("flow calls after cache hit: got = %d authorize / %d refresh, want = 1 / 1", f.authorizeCalls, f.refreshCalls)
	}
}

func TestOfflineAccessRefreshFailure(t *testing.T) {
	f := &fakeFlows{}
	s := newTestService(t, f)
	cfg := &config.Config{
		Issuer:        "https://example.com/auth",
		ClientID:      "sigstore",
		OfflineAccess: true,
	}

	// Seed a refresh token that the provider will reject.
	s.refreshTokens[refreshKey(cfg)] = "revoked"
	f.refreshErr = errors.New("refresh token is invalid or has already been claimed")

	// The failed refresh falls back to the interactive flow and replaces
	// the dead token with the new one.
	if err := s.GetCredential(api.GetCredentialRequest{ID: "repo-a", Config: cfg}, new(api.Credential)); err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if f.refreshCalls != 1 || f.authorizeCalls != 1 {
		t.Fatalf("flow calls: got = %d refresh / %d authorize, want = 1 / 1", f.refreshCalls, f.authorizeCalls)
	}
	if got := s.refreshTokens[refreshKey(cfg)]; got != "authorize-rt-1" {
		t.Fatalf("stored refresh token: got = %q, want = %q", got, "authorize-rt-1")
	}
}

func TestOfflineAccessDisabled(t *testing.T) {
	f := &fakeFlows{}
	s := newTestService(t, f)

	// Seed a token to prove it is not used when offline access is off.
	cfg := &config.Config{
		Issuer:   "https://example.com/auth",
		ClientID: "sigstore",
	}
	s.refreshTokens[refreshKey(cfg)] = "unused"

	if err := s.GetCredential(api.GetCredentialRequest{ID: "repo-a", Config: cfg}, new(api.Credential)); err == nil {
		t.Fatal("expected error from interactive fallback, got nil")
	}
	if f.authorizeCalls != 0 || f.refreshCalls != 0 {
		t.Fatalf("offline flow calls: got = %d authorize / %d refresh, want = 0 / 0", f.authorizeCalls, f.refreshCalls)
	}
	if got := s.refreshTokens[refreshKey(cfg)]; got != "unused" {
		t.Fatalf("stored refresh token: got = %q, want = %q", got, "unused")
	}
}
