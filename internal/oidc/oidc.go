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
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/browser"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauth"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/oauth2"
)

const oobRedirectURI = "urn:ietf:wg:oauth:2.0:oob"

// browserOpener is overridable for testing.
var browserOpener = browser.OpenURL

// Tokens holds the result of an OIDC token exchange.
type Tokens struct {
	IDToken      string
	RefreshToken string
}

// Flow runs an interactive OIDC authorization code flow with offline access.
type Flow struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	ConnectorID  string
	HTMLPage     string
	Input        io.Reader
	Output       io.Writer
	// BrowserOpener, if set, is used to open the login URL instead of the
	// platform default browser.
	BrowserOpener func(url string) error
}

// NewFlow creates a Flow from gitsign config, matching the interactive flow
// behavior used for identity creation (connector selection, autoclose page).
func NewFlow(cfg *config.Config, in io.Reader, out io.Writer) (*Flow, error) {
	clientSecret, err := cfg.ClientSecret()
	if err != nil {
		return nil, err
	}
	// Autoclose only works if we don't go through the identity selection page
	// (otherwise it'll show a countdown timer that doesn't work)
	autoclose := cfg.Autoclose && cfg.ConnectorID != ""
	html, err := oauth.GetInteractiveSuccessHTML(autoclose, cfg.AutocloseTimeout)
	if err != nil {
		fmt.Fprintln(out, "error getting interactive success html, using static default", err) // nolint:errcheck
		html = oauth.InteractiveSuccessHTML
	}
	flow := &Flow{
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  cfg.RedirectURL,
		ConnectorID:  cfg.ConnectorID,
		HTMLPage:     html,
		Input:        in,
		Output:       out,
	}
	// If a custom URL opener command is configured, open the login URL with it
	// instead of the platform default browser.
	if cfg.URLOpener != "" {
		open, err := fulcio.NewCommandURLOpener(cfg.URLOpener)
		if err != nil {
			return nil, err
		}
		flow.BrowserOpener = open
	}
	return flow, nil
}

// Authorize obtains tokens interactively: it opens the system browser to the
// provider's authorization endpoint (falling back to printing the URL and
// reading a verification code from Input) and exchanges the resulting code.
func (f *Flow) Authorize(ctx context.Context) (*Tokens, error) {
	provider, err := oidc.NewProvider(ctx, f.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering OIDC provider: %w", err)
	}
	cfg := oauth2.Config{
		ClientID:     f.ClientID,
		ClientSecret: f.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", oidc.ScopeOfflineAccess},
		RedirectURL:  f.RedirectURL,
	}

	state := cryptoutils.GenerateRandomURLSafeString(128)
	nonce := cryptoutils.GenerateRandomURLSafeString(128)

	doneCh := make(chan string)
	errCh := make(chan error)
	server, redirectURL, err := startRedirectListener(state, f.HTMLPage, cfg.RedirectURL, doneCh, errCh)
	if err != nil {
		return nil, fmt.Errorf("starting redirect listener: %w", err)
	}
	defer func() {
		go func() {
			_ = server.Shutdown(context.Background())
		}()
	}()
	cfg.RedirectURL = redirectURL.String()

	// Require that the OIDC provider supports PKCE.
	pkce, err := oauthflow.NewPKCE(provider)
	if err != nil {
		return nil, err
	}
	opts := append(pkce.AuthURLOpts(), oauth2.AccessTypeOffline, oidc.Nonce(nonce))
	if f.ConnectorID != "" {
		opts = append(opts, oauthflow.ConnectorIDOpt(f.ConnectorID))
	}

	authCodeURL := cfg.AuthCodeURL(state, opts...)
	open := f.BrowserOpener
	if open == nil {
		open = browserOpener
	}
	var code string
	if err := open(authCodeURL); err != nil {
		// Swap to the out of band flow if we can't open the browser.
		fmt.Fprintf(f.output(), "error opening browser: %v\n", err) // nolint:errcheck
		code = f.doOobFlow(&cfg, state, opts)
	} else {
		fmt.Fprintf(f.output(), "Your browser will now be opened to:\n%s\n", authCodeURL) // nolint:errcheck
		code, err = getCode(doneCh, errCh)
		if err != nil {
			fmt.Fprintf(f.output(), "error getting code from local server: %v\n", err) // nolint:errcheck
			code = f.doOobFlow(&cfg, state, opts)
		}
	}

	token, err := cfg.Exchange(ctx, code, append(pkce.TokenURLOpts(), oidc.Nonce(nonce))...)
	if err != nil {
		return nil, err
	}
	idToken, err := verifiedIDToken(ctx, provider, f.ClientID, token, nonce)
	if err != nil {
		return nil, err
	}
	return &Tokens{IDToken: idToken, RefreshToken: token.RefreshToken}, nil
}

// Refresh exchanges a refresh token for new tokens. The returned Tokens hold
// the rotated refresh token when the provider issues one; callers must store
// it in place of the old token, which providers such as Dex invalidate after
// a single use.
func Refresh(ctx context.Context, issuer, clientID, clientSecret, refreshToken string) (*Tokens, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering OIDC provider: %w", err)
	}
	cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
	}
	token, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, fmt.Errorf("refreshing token: %w", err)
	}
	idToken, err := verifiedIDToken(ctx, provider, clientID, token, "")
	if err != nil {
		return nil, err
	}
	return &Tokens{IDToken: idToken, RefreshToken: cmp.Or(token.RefreshToken, refreshToken)}, nil
}

// verifiedIDToken extracts the raw ID token from a token response and checks
// its signature, audience, nonce (when expected), and access token hash.
func verifiedIDToken(ctx context.Context, provider *oidc.Provider, clientID string, token *oauth2.Token, nonce string) (string, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("id_token not present in token response")
	}
	parsed, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, raw)
	if err != nil {
		return "", err
	}
	if nonce != "" && parsed.Nonce != nonce {
		return "", errors.New("nonce does not match value sent")
	}
	if parsed.AccessTokenHash != "" {
		if err := parsed.VerifyAccessToken(token.AccessToken); err != nil {
			return "", err
		}
	}
	return raw, nil
}

func (f *Flow) doOobFlow(cfg *oauth2.Config, state string, opts []oauth2.AuthCodeOption) string {
	cfg.RedirectURL = oobRedirectURI

	authURL := cfg.AuthCodeURL(state, opts...)
	fmt.Fprintln(f.output(), "Go to the following link in a browser:\n\n\t", authURL) // nolint:errcheck
	fmt.Fprint(f.output(), "Enter verification code: ")                               // nolint:errcheck
	var code string
	_, _ = fmt.Fscanf(f.input(), "%s", &code)
	// New line in case read input doesn't move cursor to next line.
	fmt.Fprintln(f.output()) // nolint:errcheck
	return code
}

func (f *Flow) input() io.Reader {
	if f.Input == nil {
		return os.Stdin
	}
	return f.Input
}

func (f *Flow) output() io.Writer {
	if f.Output == nil {
		return os.Stderr
	}
	return f.Output
}

func startRedirectListener(state, htmlPage, redirectURL string, doneCh chan string, errCh chan error) (*http.Server, *url.URL, error) {
	var listener net.Listener
	var urlListener *url.URL
	var err error

	if redirectURL == "" {
		listener, err = net.Listen("tcp", "localhost:0")
		if err != nil {
			return nil, nil, err
		}

		addr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			return nil, nil, fmt.Errorf("listener addr is not TCPAddr")
		}

		urlListener = &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("localhost:%d", addr.Port),
			Path:   "/auth/callback",
		}
	} else {
		urlListener, err = url.Parse(redirectURL)
		if err != nil {
			return nil, nil, err
		}

		listener, err = net.Listen("tcp", urlListener.Host)
		if err != nil {
			return nil, nil, err
		}
	}

	m := http.NewServeMux()
	s := &http.Server{
		Addr:              urlListener.Host,
		Handler:           m,
		ReadHeaderTimeout: 2 * time.Second,
	}

	m.HandleFunc(urlListener.Path, func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if r.FormValue("state") != state {
			errCh <- errors.New("invalid state token")
			return
		}
		doneCh <- r.FormValue("code")
		fmt.Fprint(w, htmlPage) // nolint:errcheck
	})

	go func() {
		if err := s.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	return s, urlListener, nil
}

func getCode(doneCh chan string, errCh chan error) (string, error) {
	timeoutCh := time.NewTimer(120 * time.Second)
	select {
	case code := <-doneCh:
		return code, nil
	case err := <-errCh:
		return "", err
	case <-timeoutCh.C:
		return "", errors.New("timeout")
	}
}
