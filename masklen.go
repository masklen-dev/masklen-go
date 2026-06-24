// Package masklen provides a Go client for the masklen.dev IP intelligence API.
// It supports looking up geolocation, network, privacy, and locale information
// for IP addresses. All methods are context-aware and safe for concurrent use.
package masklen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultBaseURL = "https://masklen.dev"

// Location contains geographic information about an IP address.
type Location struct {
	City        *string  `json:"city"`
	Region      *string  `json:"region"`
	Country     *string  `json:"country"`
	CountryCode *string  `json:"country_code"`
	Latitude    *float64 `json:"latitude"`
	Longitude   *float64 `json:"longitude"`
	PostalCode  *string  `json:"postal_code"`
	Timezone    *string  `json:"timezone"`
}

// Network contains network and ISP information about an IP address.
type Network struct {
	ASN          *string `json:"asn"`
	ISP          *string `json:"isp"`
	Organization *string `json:"organization"`
	Domain       *string `json:"domain"`
}

// Privacy contains privacy and threat information about an IP address.
type Privacy struct {
	VPN         bool   `json:"vpn"`
	Proxy       bool   `json:"proxy"`
	Tor         bool   `json:"tor"`
	Hosting     bool   `json:"hosting"`
	ThreatLevel string `json:"threat_level"`
}

// Locale contains locale and regional information about an IP address.
type Locale struct {
	Currency       *string  `json:"currency"`
	CurrencySymbol *string  `json:"currency_symbol"`
	CallingCode    *string  `json:"calling_code"`
	Languages      []string `json:"languages"`
	Flag           *string  `json:"flag"`
}

// LookupResult is the response returned for a single IP lookup.
type LookupResult struct {
	IP       string    `json:"ip"`
	Location *Location `json:"location"`
	Network  *Network  `json:"network"`
	Privacy  *Privacy  `json:"privacy"`
	Locale   *Locale   `json:"locale"`
}

// batchItemError holds an error response for one IP in a batch request.
type batchItemError struct {
	IP    string `json:"ip"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// BatchResult is the response returned from a batch IP lookup.
type BatchResult struct {
	Results []json.RawMessage `json:"results"`
}

// BatchItem holds one item from a BatchResult iteration.
type BatchItem struct {
	// Result is the parsed LookupResult. Valid only when IsError is false.
	Result LookupResult
	// IsError is true when this item represents a per-item API error.
	IsError bool
	// Err holds the error for this item. Non-nil only when IsError is true or
	// parsing failed.
	Err error
}

// Each parses and returns all items in the BatchResult as a slice of BatchItem.
// Each item's IsError field indicates whether the API returned an error for that
// IP. Parsing failures are also surfaced through BatchItem.Err.
func (b *BatchResult) Each() []BatchItem {
	items := make([]BatchItem, 0, len(b.Results))
	for _, raw := range b.Results {
		// Detect whether this item is an error by checking for the "error" key.
		var probe struct {
			Error *json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			items = append(items, BatchItem{
				Err: fmt.Errorf("masklen: failed to probe batch item: %w", err),
			})
			continue
		}

		if probe.Error != nil {
			var itemErr batchItemError
			if err := json.Unmarshal(raw, &itemErr); err != nil {
				items = append(items, BatchItem{
					IsError: true,
					Err:     fmt.Errorf("masklen: failed to parse batch error item: %w", err),
				})
				continue
			}
			items = append(items, BatchItem{
				IsError: true,
				Err: &APIError{
					StatusCode: 0,
					Code:       itemErr.Error.Code,
					Message:    itemErr.Error.Message,
				},
			})
			continue
		}

		var result LookupResult
		if err := json.Unmarshal(raw, &result); err != nil {
			items = append(items, BatchItem{
				Err: fmt.Errorf("masklen: failed to parse batch result item: %w", err),
			})
			continue
		}
		items = append(items, BatchItem{Result: result})
	}
	return items
}

// APIError is returned by client methods when the server responds with a
// non-2xx status code.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("masklen: API error %d: [%s] %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("masklen: API error %d: %s", e.StatusCode, e.Message)
}

// apiErrorBody is the JSON shape of an error response from the API.
type apiErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Client is the masklen.dev API client. It is safe for concurrent use.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// Option is a functional option for configuring a Client.
type Option func(*Client)

// WithBaseURL overrides the default API base URL.
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = strings.TrimRight(url, "/")
	}
}

// WithHTTPClient replaces the default HTTP client used for requests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// NewClient creates a new Client authenticated with the given API key.
// Use Option functions to override the base URL or HTTP client.
func NewClient(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:     apiKey,
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// LookupSelf looks up the caller's own IP address.
// fields optionally restricts the response to one or more field groups:
// "location", "network", "privacy", "locale".
func (c *Client) LookupSelf(ctx context.Context, fields ...string) (*LookupResult, error) {
	url := c.baseURL + "/v1/lookup"
	if len(fields) > 0 {
		url += "?fields=" + strings.Join(fields, ",")
	}
	return c.doLookup(ctx, url)
}

// Lookup looks up a specific IPv4 or IPv6 address.
// fields optionally restricts the response to one or more field groups:
// "location", "network", "privacy", "locale".
func (c *Client) Lookup(ctx context.Context, ip string, fields ...string) (*LookupResult, error) {
	url := c.baseURL + "/v1/lookup/" + ip
	if len(fields) > 0 {
		url += "?fields=" + strings.Join(fields, ",")
	}
	return c.doLookup(ctx, url)
}

// LookupBatch looks up up to 1000 IP addresses in a single request.
// fields optionally restricts the response to one or more field groups:
// "location", "network", "privacy", "locale".
func (c *Client) LookupBatch(ctx context.Context, ips []string, fields ...string) (*BatchResult, error) {
	url := c.baseURL + "/v1/lookup/batch"
	if len(fields) > 0 {
		url += "?fields=" + strings.Join(fields, ",")
	}

	body, err := json.Marshal(struct {
		IPs []string `json:"ips"`
	}{IPs: ips})
	if err != nil {
		return nil, fmt.Errorf("masklen: failed to encode batch request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("masklen: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("masklen: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("masklen: failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseAPIError(resp.StatusCode, respBody)
	}

	var result BatchResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("masklen: failed to decode response: %w", err)
	}
	return &result, nil
}

// doLookup executes a GET request and decodes the response into a LookupResult.
func (c *Client) doLookup(ctx context.Context, url string) (*LookupResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("masklen: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("masklen: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("masklen: failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseAPIError(resp.StatusCode, body)
	}

	var result LookupResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("masklen: failed to decode response: %w", err)
	}
	return &result, nil
}

// parseAPIError extracts an APIError from a non-2xx response body.
func parseAPIError(statusCode int, body []byte) *APIError {
	var errBody apiErrorBody
	// Best-effort decode; fall back to a generic message if it fails.
	_ = json.Unmarshal(body, &errBody)
	return &APIError{
		StatusCode: statusCode,
		Code:       errBody.Error.Code,
		Message:    errBody.Error.Message,
	}
}
