// Package config loads the server configuration: listeners, PostgreSQL
// connection string, TTL policy, transfer client ACL and TSIG keys.
package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// TsigKey is one shared TSIG secret. secret_b64 is standard base64,
// exactly the representation BIND/dig use for key files.
type TsigKey struct {
	Algorithm string `json:"algorithm"`
	SecretB64 string `json:"secret_b64"`
}

// Config for one authoritative server serving one zone.
type Config struct {
	Zone              string             `json:"zone"`
	ListenUDP         string             `json:"listen_udp"`
	ListenTCP         string             `json:"listen_tcp"`
	DatabaseURL       string             `json:"database_url"`
	TTLMin            uint32             `json:"ttl_min"`
	TTLMax            uint32             `json:"ttl_max"`
	TransferAllowCIDR []string           `json:"transfer_allow_cidrs"`
	TSIGKeys          map[string]TsigKey `json:"tsig_keys"`

	parsedCIDRs []*net.IPNet
	secrets     map[string]string // key name (fqdn, lower) -> raw secret
}

// Load reads, normalizes and validates a JSON config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c.Zone = dns.Fqdn(strings.ToLower(strings.TrimSpace(c.Zone)))
	if c.Zone == "." {
		return nil, fmt.Errorf("config: zone must be set")
	}
	if c.ListenUDP == "" || c.ListenTCP == "" {
		return nil, fmt.Errorf("config: listen_udp and listen_tcp are required")
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("config: database_url is required")
	}
	if c.TTLMin == 0 && c.TTLMax == 0 {
		c.TTLMin, c.TTLMax = 30, 86400
	}
	if c.TTLMin == 0 || c.TTLMax == 0 || c.TTLMin > c.TTLMax {
		return nil, fmt.Errorf("config: invalid TTL bounds min=%d max=%d", c.TTLMin, c.TTLMax)
	}
	for _, s := range c.TransferAllowCIDR {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("config: bad CIDR %q: %w", s, err)
		}
		c.parsedCIDRs = append(c.parsedCIDRs, n)
	}
	c.secrets = map[string]string{}
	for name, k := range c.TSIGKeys {
		fqdn := dns.Fqdn(strings.ToLower(name))
		// miekg/dns identifies HMAC algorithms with a trailing dot
		// ("hmac-sha256."); accept the conventional dig form as well.
		algo := dns.Fqdn(strings.ToLower(k.Algorithm))
		switch algo {
		case dns.HmacSHA1, dns.HmacSHA224, dns.HmacSHA256, dns.HmacSHA384, dns.HmacSHA512:
		default:
			return nil, fmt.Errorf("config: TSIG key %s uses unsupported algorithm %q", name, k.Algorithm)
		}
		if _, err := base64.StdEncoding.DecodeString(k.SecretB64); err != nil {
			return nil, fmt.Errorf("config: TSIG key %s secret is not valid base64: %w", name, err)
		}
		// miekg/dns's secret map stores the *base64* secret; the library
		// performs the base64 decode itself when computing the HMAC.
		c.secrets[fqdn] = k.SecretB64
	}
	return &c, nil
}

// ZoneOrigin returns the lowercased FQDN of the served zone.
func (c *Config) ZoneOrigin() string { return c.Zone }

// TransferAllowed reports whether client IP may request AXFR/IXFR.
// The ACL alone is not sufficient: TSIG must also validate (see server).
func (c *Config) TransferAllowed(ip net.IP) bool {
	for _, n := range c.parsedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// TsigSecrets returns the key map in the shape miekg/dns expects
// (Server.TsigSecret): lowercase FQDN key name -> raw secret string.
func (c *Config) TsigSecrets() map[string]string { return c.secrets }

// HasTransferKeys reports whether at least one TSIG key is configured.
func (c *Config) HasTransferKeys() bool { return len(c.secrets) > 0 }
