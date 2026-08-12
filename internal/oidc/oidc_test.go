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

package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProvider is an in-process OIDC provider implementing discovery, JWKS,
// authorization, and token endpoints. It issues real RS256-signed ID tokens
// and rotates refresh tokens on every use, rejecting reuse like Dex does.
type fakeProvider struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu      sync.Mutex
	counter int
	valid   map[string]struct{} // live refresh tokens
	nonces  map[string]string   // auth code -> nonce
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeProvider{
		key:    key,
		valid:  map[string]struct{}{},
		nonces: map[string]string{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/auth",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/keys",
			"code_challenge_methods_supported":      []string{"S256"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": "test",
				"n":   base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		code := fmt.Sprintf("code-%d", f.counter)
		f.counter++
		f.nonces[code] = q.Get("nonce")
		f.mu.Unlock()

		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		v := redirect.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		redirect.RawQuery = v.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", f.token)

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	var nonce string
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code := r.PostForm.Get("code")
		n, ok := f.nonces[code]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "invalid_grant"})
			return
		}
		delete(f.nonces, code)
		nonce = n
	case "refresh_token":
		rt := r.PostForm.Get("refresh_token")
		if _, ok := f.valid[rt]; !ok {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{
				"error":             "invalid_request",
				"error_description": "refresh token is invalid or has already been claimed",
			})
			return
		}
		delete(f.valid, rt)
	default:
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "unsupported_grant_type"})
		return
	}

	rt := fmt.Sprintf("rt-%d", f.counter)
	f.counter++
	f.valid[rt] = struct{}{}

	writeJSON(w, map[string]any{
		"access_token":  "at",
		"token_type":    "bearer",
		"expires_in":    60,
		"refresh_token": rt,
		"id_token":      f.signIDToken(nonce),
	})
}

func (f *fakeProvider) signIDToken(nonce string) string {
	now := time.Now()
	claims := map[string]any{
		"iss":            f.srv.URL,
		"sub":            "test-subject",
		"aud":            "sigstore",
		"iat":            now.Unix(),
		"exp":            now.Add(time.Minute).Unix(),
		"email":          "test@example.com",
		"email_verified": true,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test"})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// seedRefreshToken registers a live refresh token and returns it.
func (f *fakeProvider) seedRefreshToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rt := fmt.Sprintf("rt-%d", f.counter)
	f.counter++
	f.valid[rt] = struct{}{}
	return rt
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestSupportsRefreshGrant(t *testing.T) {
	ctx := t.Context()

	discovery := func(t *testing.T, extra string) string {
		t.Helper()
		var srv *httptest.Server
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"issuer": %q, "authorization_endpoint": %q, "token_endpoint": %q, "jwks_uri": %q%s}`,
				srv.URL, srv.URL+"/auth", srv.URL+"/token", srv.URL+"/keys", extra)
		})
		srv = httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		return srv.URL
	}

	for _, tc := range []struct {
		name  string
		extra string
		want  bool
	}{
		{name: "grant advertised", extra: `, "grant_types_supported": ["authorization_code", "refresh_token"]`, want: true},
		{name: "grant not advertised", extra: `, "grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"]`, want: false},
		{name: "grant types omitted", extra: "", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SupportsRefreshGrant(ctx, discovery(t, tc.extra))
			if err != nil {
				t.Fatalf("SupportsRefreshGrant: %v", err)
			}
			if got != tc.want {
				t.Errorf("SupportsRefreshGrant: got = %t, want = %t", got, tc.want)
			}
		})
	}
}

func TestRefresh(t *testing.T) {
	ctx := t.Context()
	f := newFakeProvider(t)
	rt := f.seedRefreshToken()

	tokens, err := Refresh(ctx, f.srv.URL, "sigstore", "", rt)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tokens.IDToken == "" {
		t.Error("expected ID token, got empty string")
	}
	if tokens.RefreshToken == rt || tokens.RefreshToken == "" {
		t.Errorf("expected rotated refresh token, got %q", tokens.RefreshToken)
	}

	// The rotated token works.
	rotated, err := Refresh(ctx, f.srv.URL, "sigstore", "", tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh with rotated token: %v", err)
	}
	if rotated.RefreshToken == tokens.RefreshToken {
		t.Error("expected refresh token to rotate again")
	}

	// Reusing a consumed token fails.
	if _, err := Refresh(ctx, f.srv.URL, "sigstore", "", rt); err == nil {
		t.Error("expected error reusing consumed refresh token, got nil")
	}
}

func TestAuthorize(t *testing.T) {
	ctx := t.Context()
	f := newFakeProvider(t)

	// Simulate a browser: fetch the auth URL asynchronously, following the
	// redirect back to the flow's local callback listener.
	browserOpener = func(u string) error {
		go func() {
			resp, err := http.Get(u)
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	t.Cleanup(func() { browserOpener = func(string) error { return fmt.Errorf("browser not available in tests") } })

	flow := &Flow{
		Issuer:   f.srv.URL,
		ClientID: "sigstore",
		HTMLPage: "ok",
		Input:    strings.NewReader(""),
		Output:   io.Discard,
	}
	tokens, err := flow.Authorize(ctx)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if tokens.IDToken == "" {
		t.Error("expected ID token, got empty string")
	}
	if tokens.RefreshToken == "" {
		t.Error("expected refresh token, got empty string")
	}

	// The refresh token from the interactive flow is usable.
	if _, err := Refresh(ctx, f.srv.URL, "sigstore", "", tokens.RefreshToken); err != nil {
		t.Fatalf("Refresh with token from Authorize: %v", err)
	}
}
