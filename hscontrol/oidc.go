package hscontrol

import (
	"bytes"
	"cmp"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/notifier"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"zgo.at/zcache/v2"
)

const (
	randomByteSize           = 16
	defaultOAuthOptionsCount = 3
	registerCacheExpiration  = time.Minute * 15
	registerCacheCleanup     = time.Minute * 20
)

var (
	errEmptyOIDCCallbackParams = errors.New("empty OIDC callback params")
	errNoOIDCIDToken           = errors.New("could not extract ID Token for OIDC callback")
	errNoOIDCRegistrationInfo  = errors.New("could not get registration info from cache")
	errOIDCAllowedDomains      = errors.New(
		"authenticated principal does not match any allowed domain",
	)
	errOIDCAllowedGroups = errors.New("authenticated principal is not in any allowed group")
	errOIDCAllowedUsers  = errors.New(
		"authenticated principal does not match any allowed user",
	)
	errOIDCInvalidNodeState = errors.New(
		"requested node state key expired before authorisation completed",
	)
	errOIDCNodeKeyMissing = errors.New("could not get node key from cache")
)

// RegistrationInfo contains both machine key and verifier information for OIDC validation.
type RegistrationInfo struct {
	RegistrationID types.RegistrationID
	Verifier       *string
}

type AuthProviderOIDC struct {
	serverURL         string
	cfg               *types.OIDCConfig
	state             *state.State
	registrationCache *zcache.Cache[string, RegistrationInfo]
	notifier          *notifier.Notifier

	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
}

func NewAuthProviderOIDC(
	ctx context.Context,
	serverURL string,
	cfg *types.OIDCConfig,
	state *state.State,
	notif *notifier.Notifier,
) (*AuthProviderOIDC, error) {
	var err error
	// grab oidc config if it hasn't been already
	oidcProvider, err := oidc.NewProvider(context.Background(), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider from issuer config: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  strings.TrimSuffix(serverURL, "/") + "/oidc/callback",
		Scopes:       cfg.Scope,
	}

	registrationCache := zcache.New[string, RegistrationInfo](
		registerCacheExpiration,
		registerCacheCleanup,
	)

	return &AuthProviderOIDC{
		serverURL:         serverURL,
		cfg:               cfg,
		state:             state,
		registrationCache: registrationCache,
		notifier:          notif,

		oidcProvider: oidcProvider,
		oauth2Config: oauth2Config,
	}, nil
}

func (a *AuthProviderOIDC) AuthURL(registrationID types.RegistrationID) string {
	return fmt.Sprintf(
		"%s/register/%s",
		strings.TrimSuffix(a.serverURL, "/"),
		registrationID.String())
}

func (a *AuthProviderOIDC) determineNodeExpiry(idTokenExpiration time.Time) time.Time {
	if a.cfg.UseExpiryFromToken {
		return idTokenExpiration
	}

	return time.Now().Add(a.cfg.Expiry)
}

// RegisterOIDC redirects to the OIDC provider for authentication
// Puts NodeKey in cache so the callback can retrieve it using the oidc state param
// Listens in /register/:registration_id.
func (a *AuthProviderOIDC) RegisterHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	registrationIdStr := vars["registration_id"]

	// We need to make sure we dont open for XSS style injections, if the parameter that
	// is passed as a key is not parsable/validated as a NodePublic key, then fail to render
	// the template and log an error.
	registrationId, err := types.RegistrationIDFromString(registrationIdStr)
	if err != nil {
		a.httpOIDCError(writer, req, NewHTTPError(http.StatusBadRequest, "invalid registration id", err))
		return
	}

	// Set the state and nonce cookies to protect against CSRF attacks
	state, err := setCSRFCookie(writer, req, "state")
	if err != nil {
		a.httpOIDCError(writer, req, err)
		return
	}

	// Set the state and nonce cookies to protect against CSRF attacks
	nonce, err := setCSRFCookie(writer, req, "nonce")
	if err != nil {
		a.httpOIDCError(writer, req, err)
		return
	}

	// Initialize registration info with machine key
	registrationInfo := RegistrationInfo{
		RegistrationID: registrationId,
	}

	extras := make([]oauth2.AuthCodeOption, 0, len(a.cfg.ExtraParams)+defaultOAuthOptionsCount)
	// Add PKCE verification if enabled
	if a.cfg.PKCE.Enabled {
		verifier := oauth2.GenerateVerifier()
		registrationInfo.Verifier = &verifier

		extras = append(extras, oauth2.AccessTypeOffline)

		switch a.cfg.PKCE.Method {
		case types.PKCEMethodS256:
			extras = append(extras, oauth2.S256ChallengeOption(verifier))
		case types.PKCEMethodPlain:
			// oauth2 does not have a plain challenge option, so we add it manually
			extras = append(extras, oauth2.SetAuthURLParam("code_challenge_method", "plain"), oauth2.SetAuthURLParam("code_challenge", verifier))
		}
	}

	// Add any extra parameters from configuration
	for k, v := range a.cfg.ExtraParams {
		extras = append(extras, oauth2.SetAuthURLParam(k, v))
	}
	extras = append(extras, oidc.Nonce(nonce))

	// Cache the registration info
	a.registrationCache.Set(state, registrationInfo)

	authURL := a.oauth2Config.AuthCodeURL(state, extras...)
	log.Debug().Msgf("Redirecting to %s for authentication", authURL)

	http.Redirect(writer, req, authURL, http.StatusFound)
}

type oidcCallbackTemplateConfig struct {
	User string
	Verb string
}

type oidcErrorTemplateConfig struct {
	Error     string
	Code      int
	RequestID string
	Timestamp string
	Debug     string
	Details   bool
	LoginURL  string
}

//go:embed assets/oidc_callback_template.html
var oidcCallbackTemplateContent string

var oidcCallbackTemplate = template.Must(
	template.New("oidccallback").Parse(oidcCallbackTemplateContent),
)

//go:embed assets/oidc_error_template.html
var oidcErrorTemplateContent string

var oidcErrorTemplate = template.Must(
	template.New("oidcerror").Parse(oidcErrorTemplateContent),
)

// httpOIDCError is a specialized error handler for OIDC that provides user-friendly error pages
func (a *AuthProviderOIDC) httpOIDCError(writer http.ResponseWriter, req *http.Request, err error) {
	var herr HTTPError
	if errors.As(err, &herr) {
		a.renderOIDCErrorTemplate(writer, req, herr)
	} else {
		// Create HTTPError from regular error
		herr = NewHTTPError(http.StatusInternalServerError, "An unexpected error occurred during authentication", err)
		a.renderOIDCErrorTemplate(writer, req, herr)
	}
}

// OIDCCallbackHandler handles the callback from the OIDC endpoint
// Retrieves the nkey from the state cache and adds the node to the users email user
// TODO: A confirmation page for new nodes should be added to avoid phishing vulnerabilities
// TODO: Add groups information from OIDC tokens into node HostInfo
// Listens in /oidc/callback.
func (a *AuthProviderOIDC) OIDCCallbackHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	code, state, err := extractCodeAndStateParamFromRequest(req)
	if err != nil {
		log.Error().
			Err(err).
			Str("method", "OIDCCallback").
			Str("url", req.URL.String()).
			Msg("Failed to extract code and state from OIDC callback")
		a.httpOIDCError(writer, req, err)
		return
	}

	cookieState, err := req.Cookie("state")
	if err != nil {
		log.Error().
			Err(err).
			Str("method", "OIDCCallback").
			Msg("State cookie not found in OIDC callback")
		a.httpOIDCError(writer, req, NewHTTPError(http.StatusBadRequest, "state cookie not found - please try logging in again", err))
		return
	}

	if state != cookieState.Value {
		log.Error().
			Str("method", "OIDCCallback").
			Str("state_param", state).
			Str("state_cookie", cookieState.Value).
			Msg("State parameter mismatch in OIDC callback")
		a.httpOIDCError(writer, req, NewHTTPError(http.StatusForbidden, "state parameter mismatch - possible CSRF attempt", nil))
		return
	}

	oauth2Token, err := a.getOauth2Token(req.Context(), code, state)
	if err != nil {
		log.Error().
			Err(err).
			Str("method", "OIDCCallback").
			Msg("Failed to exchange authorization code for token")
		a.httpOIDCError(writer, req, err)
		return
	}

	idToken, err := a.extractIDToken(req.Context(), oauth2Token)
	if err != nil {
		log.Error().
			Err(err).
			Str("method", "OIDCCallback").
			Msg("Failed to extract or verify ID token")
		a.httpOIDCError(writer, req, err)
		return
	}

	nonce, err := req.Cookie("nonce")
	if err != nil {
		log.Error().
			Err(err).
			Str("method", "OIDCCallback").
			Msg("Nonce cookie not found in OIDC callback")
		a.httpOIDCError(writer, req, NewHTTPError(http.StatusBadRequest, "nonce cookie not found - please try logging in again", err))
		return
	}
	if idToken.Nonce != nonce.Value {
		log.Error().
			Str("method", "OIDCCallback").
			Str("token_nonce", idToken.Nonce).
			Str("cookie_nonce", nonce.Value).
			Msg("Nonce mismatch in OIDC callback")
		a.httpOIDCError(writer, req, NewHTTPError(http.StatusForbidden, "nonce mismatch - possible replay attack", nil))
		return
	}

	nodeExpiry := a.determineNodeExpiry(idToken.Expiry)

	var claims types.OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		log.Error().
			Err(err).
			Str("method", "OIDCCallback").
			Msg("Failed to decode ID token claims")
		a.httpOIDCError(writer, req, NewHTTPError(http.StatusBadRequest, "failed to decode ID token claims", fmt.Errorf("decoding ID token claims: %w", err)))
		return
	}

	if err := validateOIDCAllowedDomains(a.cfg.AllowedDomains, &claims); err != nil {
		log.Error().
			Err(err).
			Str("method", "OIDCCallback").
			Str("email", claims.Email).
			Strs("allowed_domains", a.cfg.AllowedDomains).
			Msg("User email domain not in allowed domains")
		a.httpOIDCError(writer, req, err)
		return
	}

	if err := validateOIDCAllowedGroups(a.cfg.AllowedGroups, &claims); err != nil {
		log.Error().
			Err(err).
			Str("method", "OIDCCallback").
			Strs("user_groups", claims.Groups).
			Strs("allowed_groups", a.cfg.AllowedGroups).
			Msg("User not in allowed groups")
		a.httpOIDCError(writer, req, err)
		return
	}

	if err := validateOIDCAllowedUsers(a.cfg.AllowedUsers, &claims); err != nil {
		log.Error().
			Err(err).
			Str("method", "OIDCCallback").
			Str("user_email", claims.Email).
			Strs("allowed_users", a.cfg.AllowedUsers).
			Msg("User not in allowed users list")
		a.httpOIDCError(writer, req, err)
		return
	}

	var userinfo *oidc.UserInfo
	userinfo, err = a.oidcProvider.UserInfo(req.Context(), oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		util.LogErr(err, "could not get userinfo; only checking claim")
	}

	// If the userinfo is available, we can check if the subject matches the
	// claims, then use some of the userinfo fields to update the user.
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	if userinfo != nil && userinfo.Subject == claims.Sub {
		claims.Email = cmp.Or(claims.Email, userinfo.Email)
		claims.EmailVerified = cmp.Or(claims.EmailVerified, types.FlexibleBoolean(userinfo.EmailVerified))

		// The userinfo has some extra fields that we can use to update the user but they are only
		// available in the underlying claims struct.
		// TODO(kradalby): there might be more interesting fields here that we have not found yet.
		var userinfo2 types.OIDCUserInfo
		if err := userinfo.Claims(&userinfo2); err == nil {
			claims.Username = cmp.Or(claims.Username, userinfo2.PreferredUsername)
			claims.Name = cmp.Or(claims.Name, userinfo2.Name)
			claims.ProfilePictureURL = cmp.Or(claims.ProfilePictureURL, userinfo2.Picture)
		}
	}

	user, policyChanged, err := a.createOrUpdateUserFromClaim(&claims)
	if err != nil {
		log.Error().
			Err(err).
			Str("method", "OIDCCallback").
			Str("email", claims.Email).
			Str("sub", claims.Sub).
			Str("oidc_identifier", claims.Identifier()).
			Msg("Failed to create or update user from OIDC claims")
		a.httpOIDCError(writer, req, NewHTTPError(http.StatusInternalServerError, "failed to create or update user account", err))
		return
	}

	// Send policy update notifications if needed
	if policyChanged {
		ctx := types.NotifyCtx(context.Background(), "oidc-user-created", user.Name)
		a.notifier.NotifyAll(ctx, types.UpdateFull())
	}

	// TODO(kradalby): Is this comment right?
	// If the node exists, then the node should be reauthenticated,
	// if the node does not exist, and the machine key exists, then
	// this is a new node that should be registered.
	registrationId := a.getRegistrationIDFromState(state)

	// Register the node if it does not exist.
	if registrationId != nil {
		verb := "Reauthenticated"
		newNode, err := a.handleRegistration(user, *registrationId, nodeExpiry)
		if err != nil {
			log.Error().
				Err(err).
				Str("method", "OIDCCallback").
				Str("user", user.Name).
				Str("registration_id", registrationId.String()).
				Msg("Failed to handle node registration")
			a.httpOIDCError(writer, req, NewHTTPError(http.StatusInternalServerError, "failed to register node", err))
			return
		}

		if newNode {
			verb = "Authenticated"
		}

		// TODO(kradalby): replace with go-elem
		content, err := renderOIDCCallbackTemplate(user, verb)
		if err != nil {
			httpError(writer, err)
			return
		}

		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		if _, err := writer.Write(content.Bytes()); err != nil {
			util.LogErr(err, "Failed to write response")
		}

		return
	}

	// Neither node nor machine key was found in the state cache meaning
	// that we could not reauth nor register the node.
	log.Error().
		Str("method", "OIDCCallback").
		Str("state", state).
		Msg("Registration ID not found in state cache - session expired")
	a.httpOIDCError(writer, req, NewHTTPError(http.StatusGone, "login session expired - please try logging in again", errOIDCInvalidNodeState))

	return
}

func extractCodeAndStateParamFromRequest(
	req *http.Request,
) (string, string, error) {
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")

	if code == "" || state == "" {
		return "", "", NewHTTPError(http.StatusBadRequest, "missing required parameters - code or state parameter is empty", errEmptyOIDCCallbackParams)
	}

	return code, state, nil
}

// getOauth2Token exchanges the code from the callback for an oauth2 token.
func (a *AuthProviderOIDC) getOauth2Token(
	ctx context.Context,
	code string,
	state string,
) (*oauth2.Token, error) {
	var exchangeOpts []oauth2.AuthCodeOption

	if a.cfg.PKCE.Enabled {
		regInfo, ok := a.registrationCache.Get(state)
		if !ok {
			return nil, NewHTTPError(http.StatusNotFound, "registration info not found - session may have expired", errNoOIDCRegistrationInfo)
		}
		if regInfo.Verifier != nil {
			exchangeOpts = []oauth2.AuthCodeOption{oauth2.VerifierOption(*regInfo.Verifier)}
		}
	}

	oauth2Token, err := a.oauth2Config.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, NewHTTPError(http.StatusForbidden, "failed to exchange authorization code - the code may be invalid or expired", fmt.Errorf("could not exchange code for token: %w", err))
	}

	return oauth2Token, err
}

// extractIDToken extracts the ID token from the oauth2 token.
func (a *AuthProviderOIDC) extractIDToken(
	ctx context.Context,
	oauth2Token *oauth2.Token,
) (*oidc.IDToken, error) {
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, NewHTTPError(http.StatusBadRequest, "no ID token in OAuth2 response - check OIDC provider configuration", errNoOIDCIDToken)
	}

	verifier := a.oidcProvider.Verifier(&oidc.Config{ClientID: a.cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, NewHTTPError(http.StatusForbidden, "ID token verification failed - token may be invalid or expired", fmt.Errorf("failed to verify ID token: %w", err))
	}

	return idToken, nil
}

// validateOIDCAllowedDomains checks that if AllowedDomains is provided,
// that the authenticated principal ends with @<alloweddomain>.
func validateOIDCAllowedDomains(
	allowedDomains []string,
	claims *types.OIDCClaims,
) error {
	if len(allowedDomains) > 0 {
		if at := strings.LastIndex(claims.Email, "@"); at < 0 ||
			!slices.Contains(allowedDomains, claims.Email[at+1:]) {
			domain := ""
			if at >= 0 {
				domain = claims.Email[at+1:]
			}
			return NewHTTPError(http.StatusUnauthorized, fmt.Sprintf("email domain '%s' is not in the allowed domains list", domain), errOIDCAllowedDomains)
		}
	}

	return nil
}

// validateOIDCAllowedGroups checks if AllowedGroups is provided,
// and that the user has one group in the list.
// claims.Groups can be populated by adding a client scope named
// 'groups' that contains group membership.
func validateOIDCAllowedGroups(
	allowedGroups []string,
	claims *types.OIDCClaims,
) error {
	if len(allowedGroups) > 0 {
		for _, group := range allowedGroups {
			if slices.Contains(claims.Groups, group) {
				return nil
			}
		}

		return NewHTTPError(http.StatusUnauthorized, "user is not a member of any allowed groups", errOIDCAllowedGroups)
	}

	return nil
}

// validateOIDCAllowedUsers checks that if AllowedUsers is provided,
// that the authenticated principal is part of that list.
func validateOIDCAllowedUsers(
	allowedUsers []string,
	claims *types.OIDCClaims,
) error {
	if len(allowedUsers) > 0 &&
		!slices.Contains(allowedUsers, claims.Email) {
		return NewHTTPError(http.StatusUnauthorized, fmt.Sprintf("user '%s' is not in the allowed users list", claims.Email), errOIDCAllowedUsers)
	}

	return nil
}

// getRegistrationIDFromState retrieves the registration ID from the state.
func (a *AuthProviderOIDC) getRegistrationIDFromState(state string) *types.RegistrationID {
	regInfo, ok := a.registrationCache.Get(state)
	if !ok {
		return nil
	}

	return &regInfo.RegistrationID
}

func (a *AuthProviderOIDC) createOrUpdateUserFromClaim(
	claims *types.OIDCClaims,
) (*types.User, bool, error) {
	var user *types.User
	var err error
	var newUser bool
	var policyChanged bool
	user, err = a.state.GetUserByOIDCIdentifier(claims.Identifier())
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return nil, false, fmt.Errorf("creating or updating user: %w", err)
	}

	// if the user is still not found, create a new empty user.
	if user == nil {
		newUser = true
		user = &types.User{}
	}

	user.FromClaim(claims)

	if newUser {
		user, policyChanged, err = a.state.CreateUser(*user)
		if err != nil {
			return nil, false, fmt.Errorf("creating user: %w", err)
		}
	} else {
		_, policyChanged, err = a.state.UpdateUser(types.UserID(user.ID), func(u *types.User) error {
			*u = *user
			return nil
		})
		if err != nil {
			return nil, false, fmt.Errorf("updating user: %w", err)
		}
	}

	return user, policyChanged, nil
}

func (a *AuthProviderOIDC) handleRegistration(
	user *types.User,
	registrationID types.RegistrationID,
	expiry time.Time,
) (bool, error) {
	node, newNode, err := a.state.HandleNodeFromAuthPath(
		registrationID,
		types.UserID(user.ID),
		&expiry,
		util.RegisterMethodOIDC,
	)
	if err != nil {
		return false, fmt.Errorf("could not register node: %w", err)
	}

	// This is a bit of a back and forth, but we have a bit of a chicken and egg
	// dependency here.
	// Because the way the policy manager works, we need to have the node
	// in the database, then add it to the policy manager and then we can
	// approve the route. This means we get this dance where the node is
	// first added to the database, then we add it to the policy manager via
	// SaveNode (which automatically updates the policy manager) and then we can auto approve the routes.
	// As that only approves the struct object, we need to save it again and
	// ensure we send an update.
	// This works, but might be another good candidate for doing some sort of
	// eventbus.
	routesChanged := a.state.AutoApproveRoutes(node)
	_, policyChanged, err := a.state.SaveNode(node)
	if err != nil {
		return false, fmt.Errorf("saving auto approved routes to node: %w", err)
	}

	// Send policy update notifications if needed (from SaveNode or route changes)
	if policyChanged {
		ctx := types.NotifyCtx(context.Background(), "oidc-nodes-change", "all")
		a.notifier.NotifyAll(ctx, types.UpdateFull())
	}

	if routesChanged {
		ctx := types.NotifyCtx(context.Background(), "oidc-expiry-self", node.Hostname)
		a.notifier.NotifyByNodeID(
			ctx,
			types.UpdateSelf(node.ID),
			node.ID,
		)

		ctx = types.NotifyCtx(context.Background(), "oidc-expiry-peers", node.Hostname)
		a.notifier.NotifyWithIgnore(ctx, types.UpdatePeerChanged(node.ID), node.ID)
	}

	return newNode, nil
}

// TODO(kradalby):
// Rewrite in elem-go.
func renderOIDCCallbackTemplate(
	user *types.User,
	verb string,
) (*bytes.Buffer, error) {
	var content bytes.Buffer
	if err := oidcCallbackTemplate.Execute(&content, oidcCallbackTemplateConfig{
		User: user.Display(),
		Verb: verb,
	}); err != nil {
		return nil, fmt.Errorf("rendering OIDC callback template: %w", err)
	}

	return &content, nil
}

func (a *AuthProviderOIDC) renderOIDCErrorTemplate(
	writer http.ResponseWriter,
	req *http.Request,
	httpErr HTTPError,
) {
	requestID, _ := util.GenerateRandomStringURLSafe(8)
	
	config := oidcErrorTemplateConfig{
		Error:     httpErr.Msg,
		Code:      httpErr.Code,
		RequestID: requestID,
		Timestamp: time.Now().Format(time.RFC3339),
		LoginURL:  a.serverURL,
		Details:   true,
	}
	
	// Add debug information if available
	if httpErr.Err != nil {
		config.Debug = httpErr.Err.Error()
	}
	
	var content bytes.Buffer
	if err := oidcErrorTemplate.Execute(&content, config); err != nil {
		// Fallback to simple error if template fails
		log.Error().Err(err).Msg("Failed to render OIDC error template")
		http.Error(writer, httpErr.Msg, httpErr.Code)
		return
	}
	
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(httpErr.Code)
	if _, err := writer.Write(content.Bytes()); err != nil {
		util.LogErr(err, "Failed to write error response")
	}
}

func setCSRFCookie(w http.ResponseWriter, r *http.Request, name string) (string, error) {
	val, err := util.GenerateRandomStringURLSafe(64)
	if err != nil {
		return val, err
	}

	c := &http.Cookie{
		Path:     "/oidc/callback",
		Name:     name,
		Value:    val,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)

	return val, nil
}
