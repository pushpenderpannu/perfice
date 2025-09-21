package auth

import (
	"errors"
	"net/http"

	"perfice.adoe.dev/integration/internal/model"
)

type ApiKeyAuthenticationMethod struct {
	settings ApiKeyAuthenticationSettings
}

type ApiKeyAuthenticationSettings struct {
	Header string
	Query  string
}

func NewApiKeyAuthenticationMethod(settings ApiKeyAuthenticationSettings) model.AuthenticationMethod {
	return &ApiKeyAuthenticationMethod{settings}
}

func (m *ApiKeyAuthenticationMethod) GenerateRedirectURL(userId string) string {
	return ""
}

func (m *ApiKeyAuthenticationMethod) HandleCallback(integrationType string, code string, state string) (model.IntegrationCredentials, error) {
	return model.IntegrationCredentials{
		User:   state,
		APIKey: code,
	}, nil
}

func (m *ApiKeyAuthenticationMethod) SetRefreshCallback(callback model.RefreshCallback) {
}

type apiKeyTransport struct {
	Transport http.RoundTripper
	header    string
	query     string
	apiKey    string
}

func (t *apiKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.header != "" {
		req.Header.Add(t.header, t.apiKey)
	} else if t.query != "" {
		q := req.URL.Query()
		q.Add(t.query, t.apiKey)
		req.URL.RawQuery = q.Encode()
	} else {
		return nil, errors.New("no header or query specified for api key authentication")
	}
	return t.Transport.RoundTrip(req)
}

func (m *ApiKeyAuthenticationMethod) CreateClient(credentials model.IntegrationCredentials) (*http.Client, error) {
	return &http.Client{
		Transport: &apiKeyTransport{
			Transport: http.DefaultTransport,
			header:    m.settings.Header,
			query:     m.settings.Query,
			apiKey:    credentials.APIKey,
		},
	}, nil
}
