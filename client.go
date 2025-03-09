package tunnels

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	httpClient       *http.Client
	tunnels          map[string]Tunnel
	previousEtag     string
	server           string
	token            string
	clientName       string
	user             string
	cancelFuncs      map[string]context.CancelFunc
	cancelFuncsMutex *sync.Mutex
	certConfig       *certmagic.Config
	behindProxy      bool
	pollInterval     int
}

type ClientConfig struct {
	ServerAddr     string `json:"serverAddr,omitempty"`
	Token          string `json:"token,omitempty"`
	ClientName     string `json:"clientName,omitempty"`
	User           string `json:"user,omitempty"`
	CertDir        string `json:"certDir,omitempty"`
	AcmeEmail      string `json:"acmeEmail,omitempty"`
	AcmeUseStaging bool   `json:"acmeUseStaging,omitempty"`
	AcmeCa         string `json:"acmeCa,omitempty"`
	DnsServer      string `json:"dnsServer,omitempty"`
	BehindProxy    bool   `json:"behindProxy,omitempty"`
	PollInterval   int    `json:"pollInterval,omitempty"`
}

func NewClient(config *ClientConfig) (*Client, error) {

	if config.DnsServer != "" {
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, "udp", fmt.Sprintf("%s:53", config.DnsServer))
			},
		}
	}

	// Use random unprivileged port for ACME challenges. This is necessary
	// because of the way certmagic works, in that if it fails to bind
	// HTTPSPort (443 by default) and doesn't detect anything else binding
	// it, it fails. Obviously the boringproxy client is likely to be
	// running on a machine where 443 isn't bound, so we need a different
	// port to hack around this. See here for more details:
	// https://github.com/caddyserver/certmagic/issues/111
	var err error
	certmagic.HTTPSPort, err = randomOpenPort()
	if err != nil {
		return nil, errors.New("Failed get random port for TLS challenges")
	}

	certmagic.DefaultACME.DisableHTTPChallenge = true

	if config.CertDir != "" {
		certmagic.Default.Storage = &certmagic.FileStorage{config.CertDir}
	}

	if config.AcmeEmail != "" {
		certmagic.DefaultACME.Email = config.AcmeEmail
	}

	if config.AcmeUseStaging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}

	if config.AcmeCa != "" {
		certmagic.DefaultACME.CA = config.AcmeCa
	}

	certConfig := certmagic.NewDefault()

	httpClient := &http.Client{
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	tunnels := make(map[string]Tunnel)
	cancelFuncs := make(map[string]context.CancelFunc)
	cancelFuncsMutex := &sync.Mutex{}

	return &Client{
		httpClient:       httpClient,
		tunnels:          tunnels,
		previousEtag:     "",
		server:           config.ServerAddr,
		token:            config.Token,
		clientName:       config.ClientName,
		user:             config.User,
		cancelFuncs:      cancelFuncs,
		cancelFuncsMutex: cancelFuncsMutex,
		certConfig:       certConfig,
		behindProxy:      config.BehindProxy,
		pollInterval:     config.PollInterval,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {

	url := fmt.Sprintf("https://%s/api/clients/?client-name=%s", c.server, c.clientName)
	if c.user != "" {
		url = url + "&user=" + c.user
	}

	clientReq, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("Failed to create request for URL %s", url)
	}
	if len(c.token) > 0 {
		clientReq.Header.Add("Authorization", "bearer "+c.token)
	}
	resp, err := c.httpClient.Do(clientReq)
	if err != nil {
		return fmt.Errorf("Failed to create client. Ensure the server is running. URL: %s", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Failed to create client. HTTP Status code: %d. Failed to read body", resp.StatusCode)
		}

		msg := string(body)
		return fmt.Errorf("Failed to create client. Are the user ('%s') and token correct? HTTP Status code: %d. Message: %s", c.user, resp.StatusCode, msg)
	}

	pollChan := make(chan struct{})

	// A polling interval of 0 disables polling. Basically pollChan will
	// remain blocked and never trigger in the select below.
	if c.pollInterval > 0 {
		go func() {
			for {
				<-time.After(time.Duration(c.pollInterval) * time.Millisecond)
				pollChan <- struct{}{}
			}
		}()
	}

	for {
		err := c.PollTunnels(ctx)
		if err != nil {
			log.Print(err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-pollChan:
			// continue
		}
	}
}

func (c *Client) PollTunnels(ctx context.Context) error {

	//log.Println("PollTunnels")

	url := fmt.Sprintf("https://%s/api/tunnels?client-name=%s", c.server, c.clientName)

	listenReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	if len(c.token) > 0 {
		listenReq.Header.Add("Authorization", "bearer "+c.token)
	}

	resp, err := c.httpClient.Do(listenReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New("failed to listen (not 200 status)")
	}

	etag := resp.Header["Etag"][0]

	if etag != c.previousEtag {

		body, err := ioutil.ReadAll(resp.Body)

		tunnels := make(map[string]Tunnel)

		err = json.Unmarshal(body, &tunnels)
		if err != nil {
			return err
		}

		c.SyncTunnels(ctx, tunnels)

		c.previousEtag = etag
	}

	return nil
}

func (c *Client) SyncTunnels(ctx context.Context, serverTunnels map[string]Tunnel) {
	log.Println("SyncTunnels")

	// update tunnels to match server
	for k, newTun := range serverTunnels {

		// assume tunnels exists and hasn't changed
		bore := false

		tun, exists := c.tunnels[k]
		if !exists {
			log.Println("New tunnel", k)
			c.tunnels[k] = newTun
			bore = true
		} else if newTun != tun {
			log.Println("Restart tunnel", k)
			c.cancelFuncsMutex.Lock()
			c.cancelFuncs[k]()
			c.cancelFuncsMutex.Unlock()
			bore = true
		}

		if bore {
			cancelCtx, cancel := context.WithCancel(ctx)

			c.cancelFuncsMutex.Lock()
			c.cancelFuncs[k] = cancel
			c.cancelFuncsMutex.Unlock()

			go func(closureCtx context.Context, tun Tunnel) {
				err := c.BoreTunnel(closureCtx, tun)
				if err != nil {
					log.Println("BoreTunnel error: ", err)
				}
			}(cancelCtx, newTun)
		}
	}

	// delete any tunnels that no longer exist on server
	for k, _ := range c.tunnels {
		_, exists := serverTunnels[k]
		if !exists {
			log.Println("Kill tunnel", k)
			c.cancelFuncsMutex.Lock()
			c.cancelFuncs[k]()
			c.cancelFuncsMutex.Unlock()

			delete(c.cancelFuncs, k)
			delete(c.tunnels, k)
		}
	}
}

func (c *Client) BoreTunnel(ctx context.Context, tunnel Tunnel) error {

	log.Println("BoreTunnel", tunnel.Domain)

	signer, err := ssh.ParsePrivateKey([]byte(tunnel.TunnelPrivateKey))
	if err != nil {
		return fmt.Errorf("Unable to parse private key: %v", err)
	}

	//var hostKey ssh.PublicKey

	config := &ssh.ClientConfig{
		User: tunnel.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		//HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshHost := fmt.Sprintf("%s:%d", tunnel.ServerAddress, tunnel.ServerPort)
	client, err := ssh.Dial("tcp", sshHost, config)
	if err != nil {
		return fmt.Errorf("failed to dial: %v", err)
	}
	defer client.Close()

	bindAddr := "127.0.0.1"
	if tunnel.AllowExternalTcp {
		bindAddr = "0.0.0.0"
	}
	tunnelAddr := fmt.Sprintf("%s:%d", bindAddr, tunnel.TunnelPort)
	listener, err := client.Listen("tcp", tunnelAddr)
	if err != nil {
		return fmt.Errorf("unable to register tcp forward for %s:%d %v", bindAddr, tunnel.TunnelPort, err)
	}
	defer listener.Close()

	if tunnel.TlsTermination == "client" {

		tlsConfig := &tls.Config{
			GetCertificate: c.certConfig.GetCertificate,
			NextProtos:     []string{"h2", "acme-tls/1"},
		}
		tlsListener := tls.NewListener(listener, tlsConfig)

		httpMux := http.NewServeMux()

		httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			proxyRequest(w, r, tunnel, c.httpClient, tunnel.ClientAddress, tunnel.ClientPort, c.behindProxy)
		})

		httpServer := &http.Server{
			Handler: httpMux,
		}

		// TODO: It seems inefficient to make a separate HTTP server for each TLS-passthrough tunnel,
		// but the code is much simpler. The only alternative I've thought of so far involves storing
		// all the tunnels in a mutexed map and retrieving them from a single HTTP server, same as the
		// boringproxy server does.
		go httpServer.Serve(tlsListener)

	} else {

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					// TODO: Currently assuming an error means the
					// tunnel was manually deleted, but there
					// could be other errors that we should be
					// attempting to recover from rather than
					// breaking.
					break
					//continue
				}

				var useTls bool
				if tunnel.TlsTermination == "client-tls" {
					useTls = true
				} else {
					useTls = false
				}

				go ProxyTcp(conn, tunnel.ClientAddress, tunnel.ClientPort, useTls, c.certConfig)
			}
		}()
	}

	if tunnel.TlsTermination != "passthrough" {
		// TODO: There's still quite a bit of duplication with what the server does. Could we
		// encapsulate it into a type?
		err = c.certConfig.ManageSync(ctx, []string{tunnel.Domain})
		if err != nil {
			log.Println("CertMagic error at startup")
			log.Println(err)
		}
	}

	<-ctx.Done()

	return nil
}
