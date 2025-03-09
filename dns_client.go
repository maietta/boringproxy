package tunnels

import (
	"fmt"
	"net"
)

// DNSClient handles DNS and domain management
type DNSClient struct {
	db     *Database
	domain string
}

// NewDNSClient creates a new DNS client
func NewDNSClient(db *Database, domain string) *DNSClient {
	return &DNSClient{
		db:     db,
		domain: domain,
	}
}

// GetPublicIp attempts to determine the public IP address
func (c *DNSClient) GetPublicIp() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no public IP address found")
}

// SetDomain updates the client's domain
func (c *DNSClient) SetDomain(domain string) {
	c.domain = domain
}

// GetDomain returns the client's current domain
func (c *DNSClient) GetDomain() string {
	return c.domain
}

// BootstrapLink generates a link for domain setup
func (c *DNSClient) BootstrapLink() (string, error) {
	return fmt.Sprintf("https://%s/setup", c.domain), nil
}

// GetToken retrieves a token for domain verification
func (c *DNSClient) GetToken(requestID, code string) (*TokenData, error) {
	// For now, return a dummy token
	return &TokenData{
		Owner:  "admin",
		Client: "",
		Scopes: []string{c.domain},
	}, nil
}

// CreateRecord creates a new DNS record
func (c *DNSClient) CreateRecord(record Record) error {
	return nil
}

// Record represents a DNS record
type Record struct {
	Domain string
	Host   string
	Type   string
	Value  string
	TTL    int
}

// TokenData type is defined in database.go
