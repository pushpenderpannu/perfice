package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"perfice.adoe.dev/integration/internal/auth"
	"perfice.adoe.dev/integration/internal/model"
)

func TestDeserializeAuthenticationSettings_OAuth(t *testing.T) {
	svc := &IntegrationAuthenticationService{}

	settings := map[string]any{
		"authorize_url": "https://example.com/auth",
		"token_url":     "https://example.com/token",
		"scopes":        bson.A{"read", "write"},
		"client_id":     "my-client-id",
		"client_secret": "my-secret",
		"pkce":          true,
	}

	redirectUrl := "https://myapp.com/redirect"

	method := svc.deserializeAuthenticationSettings(settings, "oauth", redirectUrl)

	_, ok := method.(*auth.OAuthAuthenticationMethod)
	assert.True(t, ok, "method should be of type *OAuthAuthenticationMethod")
}

func TestDeserializeAuthenticationSettings_ApiKey(t *testing.T) {
	svc := &IntegrationAuthenticationService{}

	settings := map[string]any{
		"header": "X-API-Key",
		"query":  "",
	}

	redirectUrl := "https://myapp.com/redirect"

	method := svc.deserializeAuthenticationSettings(settings, "apikey", redirectUrl)

	_, ok := method.(*auth.ApiKeyAuthenticationMethod)
	assert.True(t, ok, "method should be of type *ApiKeyAuthenticationMethod")
}

func TestApiKeyAuthenticationMethod_HandleCallback(t *testing.T) {
	method := auth.NewApiKeyAuthenticationMethod(auth.ApiKeyAuthenticationSettings{})
	creds, err := method.HandleCallback("my-integration", "my-api-key", "my-user-id")
	assert.NoError(t, err)
	assert.Equal(t, "my-api-key", creds.APIKey)
	assert.Equal(t, "my-user-id", creds.User)
}

func TestApiKeyAuthenticationMethod_CreateClient(t *testing.T) {
	method := auth.NewApiKeyAuthenticationMethod(auth.ApiKeyAuthenticationSettings{
		Header: "X-API-Key",
	})
	creds := model.IntegrationCredentials{
		APIKey: "my-api-key",
	}
	client, err := method.CreateClient(creds)
	assert.NoError(t, err)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	client.Transport.RoundTrip(req)
	assert.Equal(t, "my-api-key", req.Header.Get("X-API-Key"))
}
