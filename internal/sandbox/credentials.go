package sandbox

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// greyproxyAPIBase is the default greyproxy API URL.
	greyproxyAPIBase = "http://localhost:43080"

	// placeholderPrefix identifies credential placeholders.
	placeholderPrefix = "greyproxy:credential:v1"

	// defaultSessionTTL is the default session TTL in seconds.
	defaultSessionTTL = 900

	// heartbeatInterval is how often heartbeats are sent.
	heartbeatInterval = 60 * time.Second
)

// WellKnownCredentialEnvVars lists env var names that commonly contain secrets.
var WellKnownCredentialEnvVars = []string{
	// Tier 1: AI/LLM Providers
	"ANTHROPIC_API_KEY", "CLAUDE_API_KEY",
	"OPENAI_API_KEY", "OPENAI_ORG_ID",
	"GOOGLE_API_KEY", "GEMINI_API_KEY",
	"NVIDIA_API_KEY", "COHERE_API_KEY",
	"HUGGINGFACE_TOKEN", "HF_TOKEN", "HF_API_KEY",
	"MISTRAL_API_KEY", "PERPLEXITY_API_KEY", "GROQ_API_KEY",
	"TOGETHER_API_KEY", "FIREWORKS_API_KEY", "REPLICATE_API_TOKEN",
	"OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "XAI_API_KEY",

	// Tier 2: Cloud Providers
	"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
	"GCP_API_KEY",
	"AZURE_CLIENT_SECRET", "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID",
	"DIGITALOCEAN_ACCESS_TOKEN", "DO_API_TOKEN",
	"CLOUDFLARE_API_KEY", "CLOUDFLARE_API_TOKEN", "CF_API_KEY",
	"FLY_API_TOKEN", "HEROKU_API_KEY", "VERCEL_TOKEN", "NETLIFY_AUTH_TOKEN",

	// Tier 3: Payment / Financial
	"STRIPE_SECRET_KEY", "STRIPE_API_KEY",
	"PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET",
	"SQUARE_ACCESS_TOKEN", "PLAID_SECRET", "PLAID_CLIENT_ID",
	"GOCARDLESS_ACCESS_TOKEN",

	// Tier 4: Dev Tools / SCM
	"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_CLIENT_SECRET",
	"GITLAB_TOKEN", "GLAB_TOKEN", "CI_JOB_TOKEN",
	"BITBUCKET_TOKEN", "BITBUCKET_CLIENT_SECRET",
	"NPM_TOKEN", "NPM_AUTH_TOKEN", "PYPI_TOKEN", "TWINE_PASSWORD",
	"DOCKER_PASSWORD", "DOCKERHUB_TOKEN",
	"SNYK_TOKEN", "SENTRY_AUTH_TOKEN", "SENTRY_DSN",
	"DD_API_KEY", "DATADOG_API_KEY",
	"NEW_RELIC_LICENSE_KEY", "NEW_RELIC_API_KEY", "GRAFANA_API_KEY",
	"PLANETSCALE_SERVICE_TOKEN",
	"SUPABASE_SERVICE_KEY", "SUPABASE_ANON_KEY",
	"LINEAR_API_KEY", "CIRCLECI_TOKEN",

	// Tier 5: Communication / SaaS
	"TWILIO_AUTH_TOKEN", "TWILIO_ACCOUNT_SID",
	"SENDGRID_API_KEY", "MAILGUN_API_KEY", "MAILCHIMP_API_KEY",
	"SLACK_TOKEN", "SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL",
	"DISCORD_TOKEN", "DISCORD_BOT_TOKEN", "TELEGRAM_BOT_TOKEN",
	"INTERCOM_ACCESS_TOKEN", "ZENDESK_API_TOKEN", "HUBSPOT_API_KEY",

	// Tier 6: Maps / Geo / Media
	"GOOGLE_MAPS_API_KEY", "MAPBOX_ACCESS_TOKEN",
	"ALGOLIA_API_KEY", "ALGOLIA_APP_ID",
	"CLOUDINARY_URL", "CLOUDINARY_API_SECRET",
	"CONTENTFUL_ACCESS_TOKEN", "SHOPIFY_ACCESS_TOKEN", "SHOPIFY_API_SECRET",

	// Tier 7: Database Credentials
	"DATABASE_URL", "DATABASE_PASSWORD", "DB_PASSWORD",
	"PGPASSWORD", "POSTGRES_PASSWORD",
	"MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD",
	"MONGO_URI", "MONGODB_URI",
	"REDIS_URL", "REDIS_PASSWORD",

	// Tier 8: Auth / Crypto
	"JWT_SECRET", "JWT_SIGNING_KEY",
	"SESSION_SECRET", "SECRET_KEY", "APP_SECRET",
	"ENCRYPTION_KEY", "MASTER_KEY",
	"OAUTH_CLIENT_SECRET", "VAULT_TOKEN",
}

// credentialSuffixPatterns matches env var names by suffix pattern.
var credentialSuffixPatterns = []string{
	"_API_KEY",
	"_SECRET_KEY",
	"_SECRET",
	"_TOKEN",
	"_PASSWORD",
	"_AUTH_TOKEN",
	"_ACCESS_TOKEN",
	"_ACCESS_KEY",
	"_PRIVATE_KEY",
}

// nonCredentialVars lists env vars that match patterns but are not secrets.
var nonCredentialVars = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "SHELL": true,
	"TERM": true, "LANG": true, "LC_ALL": true,
	"PWD": true, "OLDPWD": true, "SHLVL": true,
	"EDITOR": true, "VISUAL": true, "PAGER": true,
	"DISPLAY": true, "XDG_SESSION_TYPE": true,
	"GREYWALL_SANDBOX": true,
	"GOOGLE_APPLICATION_CREDENTIALS": true, // file path, not a credential
	"STRIPE_PUBLISHABLE_KEY": true,          // public key, not secret
}

// CredentialMapping holds a detected credential and its placeholder.
type CredentialMapping struct {
	EnvVar      string
	RealValue   string
	Placeholder string
}

// DetectCredentials scans the environment for credential env vars.
// extraVars is an optional list of additional env var names to treat as credentials
// (for vars that don't match the well-known list or suffix patterns).
// ignoreVars is an optional list of env var names to exclude from detection
// (for vars that match patterns but should not be treated as secrets).
// Returns mappings for all detected credentials.
func DetectCredentials(env []string, sessionID string, extraVars, ignoreVars []string) ([]CredentialMapping, error) {
	wellKnown := make(map[string]bool, len(WellKnownCredentialEnvVars)+len(extraVars))
	for _, v := range WellKnownCredentialEnvVars {
		wellKnown[v] = true
	}
	for _, v := range extraVars {
		wellKnown[v] = true
	}

	ignored := make(map[string]bool, len(nonCredentialVars)+len(ignoreVars))
	for k, v := range nonCredentialVars {
		ignored[k] = v
	}
	for _, v := range ignoreVars {
		ignored[v] = true
	}

	var mappings []CredentialMapping
	for _, entry := range env {
		idx := strings.Index(entry, "=")
		if idx < 0 {
			continue
		}
		key := entry[:idx]
		value := entry[idx+1:]

		if value == "" || ignored[key] {
			continue
		}

		if wellKnown[key] || matchesSuffixPattern(key) {
			placeholder, err := generatePlaceholder(sessionID)
			if err != nil {
				return nil, fmt.Errorf("generate placeholder for %s: %w", key, err)
			}
			mappings = append(mappings, CredentialMapping{
				EnvVar:      key,
				RealValue:   value,
				Placeholder: placeholder,
			})
		}
	}
	return mappings, nil
}

// matchesSuffixPattern checks if an env var name matches any suffix pattern.
func matchesSuffixPattern(key string) bool {
	upper := strings.ToUpper(key)
	for _, suffix := range credentialSuffixPatterns {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}

// generatePlaceholder creates a credential placeholder string.
func generatePlaceholder(sessionID string) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s:%s", placeholderPrefix, sessionID, hex.EncodeToString(b)), nil
}

// GenerateSessionID creates a unique session ID for this sandbox instance.
func GenerateSessionID() (string, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return "gw-" + hex.EncodeToString(b), nil
}

// SubstituteEnv replaces credential values with placeholders in the environment.
// If a mapping's env var is not present in the environment, it is appended
// (this happens for global credentials injected via --inject).
// Returns the modified environment.
func SubstituteEnv(env []string, mappings []CredentialMapping) []string {
	// Build lookup: envVar -> placeholder
	lookup := make(map[string]string, len(mappings))
	for _, m := range mappings {
		lookup[m.EnvVar] = m.Placeholder
	}

	seen := make(map[string]bool, len(mappings))
	result := make([]string, len(env))
	for i, entry := range env {
		idx := strings.Index(entry, "=")
		if idx < 0 {
			result[i] = entry
			continue
		}
		key := entry[:idx]
		if placeholder, ok := lookup[key]; ok {
			result[i] = key + "=" + placeholder
			seen[key] = true
		} else {
			result[i] = entry
		}
	}

	// Append any mappings for env vars not already present
	for _, m := range mappings {
		if !seen[m.EnvVar] {
			result = append(result, m.EnvVar+"="+m.Placeholder)
		}
	}

	return result
}

// sessionRequest is the JSON body for POST /api/sessions.
type sessionRequest struct {
	SessionID         string            `json:"session_id"`
	ContainerName     string            `json:"container_name"`
	Mappings          map[string]string `json:"mappings,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	GlobalCredentials []string          `json:"global_credentials,omitempty"`
	TTLSeconds        int               `json:"ttl_seconds"`
}

// SessionMetadata holds context about the sandboxed process for dashboard display.
type SessionMetadata struct {
	Pwd        string // Working directory
	Cmd        string // Command name
	Args       string // Command arguments
	BinaryPath string // Absolute path to the binary
	PID        string // PID of the greywall process
}

// sessionResponse is the JSON response from POST /api/sessions.
type sessionResponse struct {
	SessionID         string            `json:"session_id"`
	ExpiresAt         string            `json:"expires_at"`
	CredentialCount   int               `json:"credential_count"`
	GlobalCredentials map[string]string `json:"global_credentials,omitempty"` // label -> placeholder
}

// RegisterSessionResult holds the result of a session registration.
type RegisterSessionResult struct {
	// GlobalCredentials maps label -> placeholder for resolved global credentials.
	GlobalCredentials map[string]string
}

// RegisterSession registers credential mappings with greyproxy.
// globalCredLabels is an optional list of global credential labels to resolve.
// metadata is optional context about the sandboxed process (for dashboard display).
// Returns the resolved global credential placeholders (label -> placeholder).
func RegisterSession(sessionID, containerName string, mappings []CredentialMapping, globalCredLabels []string, metadata *SessionMetadata, apiBase string) (*RegisterSessionResult, error) {
	if apiBase == "" {
		apiBase = greyproxyAPIBase
	}

	var reqMappings map[string]string
	var reqLabels map[string]string
	if len(mappings) > 0 {
		reqMappings = make(map[string]string, len(mappings))
		reqLabels = make(map[string]string, len(mappings))
		for _, m := range mappings {
			reqMappings[m.Placeholder] = m.RealValue
			reqLabels[m.Placeholder] = m.EnvVar
		}
	}

	var reqMetadata map[string]string
	if metadata != nil {
		reqMetadata = make(map[string]string)
		if metadata.Pwd != "" {
			reqMetadata["pwd"] = metadata.Pwd
		}
		if metadata.Cmd != "" {
			reqMetadata["cmd"] = metadata.Cmd
		}
		if metadata.Args != "" {
			reqMetadata["args"] = metadata.Args
		}
		if metadata.BinaryPath != "" {
			reqMetadata["binary_path"] = metadata.BinaryPath
		}
		if metadata.PID != "" {
			reqMetadata["pid"] = metadata.PID
		}
	}

	body := sessionRequest{
		SessionID:         sessionID,
		ContainerName:     containerName,
		Mappings:          reqMappings,
		Labels:            reqLabels,
		Metadata:          reqMetadata,
		GlobalCredentials: globalCredLabels,
		TTLSeconds:        defaultSessionTTL,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal session request: %w", err)
	}

	resp, err := http.Post(apiBase+"/api/sessions", "application/json", bytes.NewReader(data)) //nolint:gosec // local API call
	if err != nil {
		return nil, fmt.Errorf("register session: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register session: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var sessResp sessionResponse
	if err := json.Unmarshal(respBody, &sessResp); err != nil {
		return nil, fmt.Errorf("parse session response: %w", err)
	}

	return &RegisterSessionResult{
		GlobalCredentials: sessResp.GlobalCredentials,
	}, nil
}

// HeartbeatSession sends a heartbeat to keep the session alive.
func HeartbeatSession(sessionID, apiBase string) error {
	if apiBase == "" {
		apiBase = greyproxyAPIBase
	}

	resp, err := http.Post(apiBase+"/api/sessions/"+sessionID+"/heartbeat", "application/json", nil)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("session expired or not found")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat: HTTP %d", resp.StatusCode)
	}
	return nil
}

// DeleteSession removes a session from greyproxy.
func DeleteSession(sessionID, apiBase string) error {
	if apiBase == "" {
		apiBase = greyproxyAPIBase
	}

	req, err := http.NewRequest(http.MethodDelete, apiBase+"/api/sessions/"+sessionID, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// StartHeartbeatLoop starts a goroutine that sends heartbeats every interval.
// It re-registers the session if heartbeat returns 404.
// Returns a stop function.
func StartHeartbeatLoop(sessionID, containerName string, mappings []CredentialMapping, globalCredLabels []string, metadata *SessionMetadata, apiBase string, debug bool) func() {
	stop := make(chan struct{})

	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				err := HeartbeatSession(sessionID, apiBase)
				if err != nil {
					if debug {
						fmt.Fprintf(os.Stderr, "[greywall:cred] heartbeat failed: %v, re-registering\n", err)
					}
					// Re-register on failure (session may have expired or proxy restarted)
					if _, regErr := RegisterSession(sessionID, containerName, mappings, globalCredLabels, metadata, apiBase); regErr != nil {
						if debug {
							fmt.Fprintf(os.Stderr, "[greywall:cred] re-register failed: %v\n", regErr)
						}
					}
				}
			}
		}
	}()

	return func() {
		close(stop)
	}
}

// SensitiveGreyproxyFiles returns paths to greyproxy files that must not be
// readable from inside the sandbox (encryption key and CA private key).
func SensitiveGreyproxyFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	return []string{
		// Linux
		home + "/.local/share/greyproxy/session.key",
		home + "/.local/share/greyproxy/ca-key.pem",
		// macOS
		home + "/Library/Application Support/greyproxy/session.key",
		home + "/Library/Application Support/greyproxy/ca-key.pem",
	}
}
