# go-masklen

Go client for the [masklen.dev](https://masklen.dev) IP intelligence API. Provides geolocation, network, privacy, and locale data for any IPv4 or IPv6 address.

## Installation

```bash
go get github.com/masklen-dev/masklen-go
```

Requires Go 1.21 or later. Zero external dependencies.

## Quick Start

### Look up your own IP

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/masklen-dev/masklen-go"
)

func main() {
    client := masklen.NewClient("your-api-key")

    result, err := client.LookupSelf(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Your IP: %s\n", result.IP)
    if result.Location != nil && result.Location.Country != nil {
        fmt.Printf("Country: %s\n", *result.Location.Country)
    }
}
```

### Look up a specific IP address

```go
client := masklen.NewClient("your-api-key")

result, err := client.Lookup(context.Background(), "8.8.8.8")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("IP: %s\n", result.IP)
if result.Network != nil && result.Network.ISP != nil {
    fmt.Printf("ISP: %s\n", *result.Network.ISP)
}
if result.Privacy != nil {
    fmt.Printf("VPN: %v, Tor: %v, Threat: %s\n",
        result.Privacy.VPN,
        result.Privacy.Tor,
        result.Privacy.ThreatLevel,
    )
}
```

### Batch lookup

```go
client := masklen.NewClient("your-api-key")

batch, err := client.LookupBatch(context.Background(), []string{
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
})
if err != nil {
    log.Fatal(err)
}

for _, item := range batch.Each() {
    if item.IsError {
        // item.Err is an *APIError with per-item code and message
        fmt.Printf("Error: %v\n", item.Err)
        continue
    }
    if item.Err != nil {
        fmt.Printf("Parse error: %v\n", item.Err)
        continue
    }
    fmt.Printf("IP: %s\n", item.Result.IP)
}
```

## Method Signatures

```go
func NewClient(apiKey string, opts ...Option) *Client

func (c *Client) LookupSelf(ctx context.Context, fields ...string) (*LookupResult, error)
func (c *Client) Lookup(ctx context.Context, ip string, fields ...string) (*LookupResult, error)
func (c *Client) LookupBatch(ctx context.Context, ips []string, fields ...string) (*BatchResult, error)

func (b *BatchResult) Each() []BatchItem
```

## Options

```go
// Override the API base URL (useful for testing or proxies)
masklen.WithBaseURL("https://custom-endpoint.example.com")

// Supply a custom *http.Client (timeouts, transport, etc.)
masklen.WithHTTPClient(&http.Client{Timeout: 5 * time.Second})
```

Example:

```go
client := masklen.NewClient(
    "your-api-key",
    masklen.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),
)
```

## Field Filtering

All three methods accept an optional `fields` variadic argument. Pass one or more
of `"location"`, `"network"`, `"privacy"`, `"locale"` to restrict which field
groups are returned. Omitting `fields` returns all groups.

```go
// Only fetch location and privacy data
result, err := client.Lookup(ctx, "8.8.8.8", "location", "privacy")

// Only fetch network data in a batch request
batch, err := client.LookupBatch(ctx, ips, "network")
```

## Error Handling

Non-2xx responses are returned as `*APIError`:

```go
result, err := client.Lookup(ctx, "8.8.8.8")
if err != nil {
    var apiErr *masklen.APIError
    if errors.As(err, &apiErr) {
        fmt.Printf("Status: %d, Code: %s, Message: %s\n",
            apiErr.StatusCode,
            apiErr.Code,
            apiErr.Message,
        )
    } else {
        // Network or other transport-level error
        fmt.Printf("Request failed: %v\n", err)
    }
    return
}
```

Per-item errors in batch responses are surfaced through `BatchResult.Each()` as
`*APIError` values with `isError == true`.

## Data Types

### LookupResult

| Field      | Type        | Description                       |
|------------|-------------|-----------------------------------|
| `ip`       | `string`    | The queried IP address            |
| `location` | `*Location` | Geographic location data          |
| `network`  | `*Network`  | ASN, ISP, and organization data   |
| `privacy`  | `*Privacy`  | VPN, proxy, Tor, and threat data  |
| `locale`   | `*Locale`   | Currency, language, and flag data |

### Location

| Field          | Type      |
|----------------|-----------|
| `city`         | `*string` |
| `region`       | `*string` |
| `country`      | `*string` |
| `country_code` | `*string` |
| `latitude`     | `*float64`|
| `longitude`    | `*float64`|
| `postal_code`  | `*string` |
| `timezone`     | `*string` |

### Network

| Field          | Type      |
|----------------|-----------|
| `asn`          | `*string` |
| `isp`          | `*string` |
| `organization` | `*string` |
| `domain`       | `*string` |

### Privacy

| Field          | Type     |
|----------------|----------|
| `vpn`          | `bool`   |
| `proxy`        | `bool`   |
| `tor`          | `bool`   |
| `hosting`      | `bool`   |
| `threat_level` | `string` |

### Locale

| Field             | Type       |
|-------------------|------------|
| `currency`        | `*string`  |
| `currency_symbol` | `*string`  |
| `calling_code`    | `*string`  |
| `languages`       | `[]string` |
| `flag`            | `*string`  |

## License

MIT
