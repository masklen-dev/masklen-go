package masklen_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/masklen-dev/masklen-go"
)

// helpers

func ptr[T any](v T) *T { return &v }

func newTestClient(t *testing.T, mux *http.ServeMux) (*masklen.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := masklen.NewClient(
		"test-api-key",
		masklen.WithBaseURL(srv.URL),
		masklen.WithHTTPClient(srv.Client()),
	)
	return client, srv
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustJSON: %v", err)
	}
	return string(b)
}

// LookupSelf

func TestLookupSelf(t *testing.T) {
	want := masklen.LookupResult{
		IP: "203.0.113.1",
		Location: &masklen.Location{
			City:        ptr("San Francisco"),
			Country:     ptr("United States"),
			CountryCode: ptr("US"),
			Latitude:    ptr(37.7749),
			Longitude:   ptr(-122.4194),
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/lookup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-api-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	})

	client, _ := newTestClient(t, mux)
	got, err := client.LookupSelf(context.Background())
	if err != nil {
		t.Fatalf("LookupSelf returned error: %v", err)
	}
	if got.IP != want.IP {
		t.Errorf("IP: got %q, want %q", got.IP, want.IP)
	}
	if got.Location == nil {
		t.Fatal("Location is nil")
	}
	if *got.Location.City != *want.Location.City {
		t.Errorf("City: got %q, want %q", *got.Location.City, *want.Location.City)
	}
}

func TestLookupSelf_FieldsQueryParam(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/lookup", func(w http.ResponseWriter, r *http.Request) {
		fields := r.URL.Query().Get("fields")
		if fields != "location,network" {
			http.Error(w, "unexpected fields: "+fields, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(masklen.LookupResult{IP: "1.2.3.4"})
	})

	client, _ := newTestClient(t, mux)
	got, err := client.LookupSelf(context.Background(), "location", "network")
	if err != nil {
		t.Fatalf("LookupSelf with fields returned error: %v", err)
	}
	if got.IP != "1.2.3.4" {
		t.Errorf("IP: got %q, want %q", got.IP, "1.2.3.4")
	}
}

// Lookup

func TestLookup(t *testing.T) {
	want := masklen.LookupResult{
		IP: "8.8.8.8",
		Network: &masklen.Network{
			ASN:          ptr("AS15169"),
			ISP:          ptr("Google LLC"),
			Organization: ptr("Google Public DNS"),
		},
		Privacy: &masklen.Privacy{
			VPN:         false,
			Proxy:       false,
			Tor:         false,
			Hosting:     true,
			ThreatLevel: "low",
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/lookup/8.8.8.8", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	})

	client, _ := newTestClient(t, mux)
	got, err := client.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if got.IP != want.IP {
		t.Errorf("IP: got %q, want %q", got.IP, want.IP)
	}
	if got.Network == nil {
		t.Fatal("Network is nil")
	}
	if *got.Network.ASN != *want.Network.ASN {
		t.Errorf("ASN: got %q, want %q", *got.Network.ASN, *want.Network.ASN)
	}
	if got.Privacy == nil {
		t.Fatal("Privacy is nil")
	}
	if got.Privacy.ThreatLevel != want.Privacy.ThreatLevel {
		t.Errorf("ThreatLevel: got %q, want %q", got.Privacy.ThreatLevel, want.Privacy.ThreatLevel)
	}
}

func TestLookup_IPv6(t *testing.T) {
	const ip = "2001:4860:4860::8888"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/lookup/"+ip, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(masklen.LookupResult{IP: ip})
	})

	client, _ := newTestClient(t, mux)
	got, err := client.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("Lookup IPv6 returned error: %v", err)
	}
	if got.IP != ip {
		t.Errorf("IP: got %q, want %q", got.IP, ip)
	}
}

// LookupBatch

func TestLookupBatch(t *testing.T) {
	city1 := "Mountain View"
	city2 := "Palo Alto"

	successItem := masklen.LookupResult{
		IP: "8.8.8.8",
		Location: &masklen.Location{
			City: &city1,
		},
	}
	successItem2 := masklen.LookupResult{
		IP: "1.1.1.1",
		Location: &masklen.Location{
			City: &city2,
		},
	}

	type batchResponse struct {
		Results []any `json:"results"`
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/lookup/batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var reqBody struct {
			IPs []string `json:"ips"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(reqBody.IPs) != 2 {
			http.Error(w, "expected 2 IPs", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(batchResponse{
			Results: []any{successItem, successItem2},
		})
	})

	client, _ := newTestClient(t, mux)
	got, err := client.LookupBatch(context.Background(), []string{"8.8.8.8", "1.1.1.1"})
	if err != nil {
		t.Fatalf("LookupBatch returned error: %v", err)
	}
	if len(got.Results) != 2 {
		t.Fatalf("Results length: got %d, want 2", len(got.Results))
	}

	items := got.Each()
	if len(items) != 2 {
		t.Fatalf("Each returned %d items, want 2", len(items))
	}
	for i, item := range items {
		if item.Err != nil {
			t.Fatalf("item %d: unexpected error: %v", i, item.Err)
		}
		if item.IsError {
			t.Fatalf("item %d: IsError=true for success item", i)
		}
	}
	if items[0].Result.IP != "8.8.8.8" {
		t.Errorf("item 0 IP: got %q, want %q", items[0].Result.IP, "8.8.8.8")
	}
	if items[0].Result.Location == nil || *items[0].Result.Location.City != city1 {
		t.Errorf("item 0 City: got wrong value")
	}
	if items[1].Result.IP != "1.1.1.1" {
		t.Errorf("item 1 IP: got %q, want %q", items[1].Result.IP, "1.1.1.1")
	}
}

func TestLookupBatch_MixedResults(t *testing.T) {
	type errorDetail struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	type itemError struct {
		IP    string      `json:"ip"`
		Error errorDetail `json:"error"`
	}

	successItem := masklen.LookupResult{IP: "8.8.8.8"}
	errorItem := itemError{
		IP: "not-an-ip",
		Error: errorDetail{
			Code:    "INVALID_IP",
			Message: "not a valid IP address",
		},
	}

	type batchResponse struct {
		Results []any `json:"results"`
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/lookup/batch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(batchResponse{
			Results: []any{successItem, errorItem},
		})
	})

	client, _ := newTestClient(t, mux)
	got, err := client.LookupBatch(context.Background(), []string{"8.8.8.8", "not-an-ip"})
	if err != nil {
		t.Fatalf("LookupBatch returned error: %v", err)
	}

	items := got.Each()

	var successItems []masklen.BatchItem
	var errorItems []masklen.BatchItem
	for _, item := range items {
		if item.IsError || item.Err != nil {
			errorItems = append(errorItems, item)
		} else {
			successItems = append(successItems, item)
		}
	}

	if len(successItems) != 1 {
		t.Errorf("expected 1 success result, got %d", len(successItems))
	}
	if len(errorItems) != 1 {
		t.Errorf("expected 1 error result, got %d", len(errorItems))
	}
	if len(errorItems) > 0 {
		apiErr, ok := errorItems[0].Err.(*masklen.APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T", errorItems[0].Err)
		}
		if apiErr.Code != "INVALID_IP" {
			t.Errorf("APIError.Code: got %q, want %q", apiErr.Code, "INVALID_IP")
		}
	}
}

// APIError

func TestAPIError_Unauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/lookup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(mustJSON(t, map[string]any{
			"error": map[string]string{
				"code":    "UNAUTHORIZED",
				"message": "invalid API key",
			},
		})))
	})

	client, _ := newTestClient(t, mux)
	_, err := client.LookupSelf(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*masklen.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode: got %d, want %d", apiErr.StatusCode, http.StatusUnauthorized)
	}
	if apiErr.Code != "UNAUTHORIZED" {
		t.Errorf("Code: got %q, want %q", apiErr.Code, "UNAUTHORIZED")
	}
	if apiErr.Message != "invalid API key" {
		t.Errorf("Message: got %q, want %q", apiErr.Message, "invalid API key")
	}
	if !strings.Contains(apiErr.Error(), "UNAUTHORIZED") {
		t.Errorf("Error() does not contain code: %q", apiErr.Error())
	}
}

func TestAPIError_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/lookup/999.999.999.999", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(mustJSON(t, map[string]any{
			"error": map[string]string{
				"code":    "NOT_FOUND",
				"message": "IP address not found",
			},
		})))
	})

	client, _ := newTestClient(t, mux)
	_, err := client.Lookup(context.Background(), "999.999.999.999")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*masklen.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode: got %d, want %d", apiErr.StatusCode, http.StatusNotFound)
	}
}

func TestAPIError_ErrorString(t *testing.T) {
	err := &masklen.APIError{StatusCode: 429, Code: "RATE_LIMITED", Message: "too many requests"}
	s := err.Error()
	if !strings.Contains(s, "429") {
		t.Errorf("Error() missing status code: %q", s)
	}
	if !strings.Contains(s, "RATE_LIMITED") {
		t.Errorf("Error() missing code: %q", s)
	}
	if !strings.Contains(s, "too many requests") {
		t.Errorf("Error() missing message: %q", s)
	}

	// Error without code
	err2 := &masklen.APIError{StatusCode: 500, Message: "internal server error"}
	s2 := err2.Error()
	if !strings.Contains(s2, "500") {
		t.Errorf("Error() missing status code: %q", s2)
	}
}

// NewClient options

func TestWithBaseURL(t *testing.T) {
	mux := http.NewServeMux()
	called := false
	mux.HandleFunc("/v1/lookup", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(masklen.LookupResult{IP: "1.2.3.4"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Provide base URL with a trailing slash to verify it is trimmed.
	client := masklen.NewClient(
		"key",
		masklen.WithBaseURL(srv.URL+"/"),
		masklen.WithHTTPClient(srv.Client()),
	)
	_, err := client.LookupSelf(context.Background())
	if err != nil {
		t.Fatalf("LookupSelf returned error: %v", err)
	}
	if !called {
		t.Error("handler was never called")
	}
}

func TestContextCancellation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/lookup", func(w http.ResponseWriter, r *http.Request) {
		// The client will have cancelled before we respond.
		<-r.Context().Done()
		http.Error(w, "cancelled", http.StatusServiceUnavailable)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := masklen.NewClient("key", masklen.WithBaseURL(srv.URL), masklen.WithHTTPClient(srv.Client()))
	_, err := client.LookupSelf(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}
