# boringproxy

boringproxy development is sponsored by [TakingNames.io](https://takingnames.io).
boringproxy offers full integration with TakingNames.io, providing the simplest
way to get up and running with your own domain. More information [here](https://takingnames.io/blog/introducing-takingnames-io),
and a demo video of boringproxy working with TakingNames.io [here](https://youtu.be/9hf72-fYTts).

<a href='https://takingnames.io/blog/introducing-takingnames-io'>
  <img src='https://user-images.githubusercontent.com/7820200/148330003-5f8062ff-22b2-423d-b945-3db87abf10e5.png' width='400'></img>
</a>

# What is boringproxy?

boringproxy is a reverse proxy that makes your local services accessible from the internet securely. It consists of two parts:

1. **Gateway Server**: A server with a public IP address that handles incoming traffic and SSL certificates
2. **Client**: Your local machine (like a development laptop) where your actual services run

```ascii
                                     │
┌──────────────┐      HTTPS      ┌──┤ Internet
│   Browser    │ ─────────────── │  │
└──────────────┘                 │  │
                                 │  │
                            ┌────┴──┴────┐
                            │  Gateway   │
                            │  Server    │
                            └────────────┘
                                  │
                                  │
                            Secure Tunnel
                                  │
                                  ▼
                            ┌────────────┐
                            │   Client   │
                            │  Machine   │
                            └────────────┘
                                  │
                                  │
                                  ▼
                            ┌────────────┐
                            │Your Service│
                            │(localhost) │
                            └────────────┘
```

# Quick Start Guide

## 1. Setting Up the Gateway Server

You need a server with:
- Public IP address
- Domain name pointing to it
- Ports 80 and 443 available

### Install on Gateway Server
```bash
# Clone and build
git clone https://github.com/maietta/boringproxy
cd boringproxy
./install_go.sh
source $HOME/.bashrc
./scripts/generate_logo.sh
cd cmd/boringproxy
go build

# Allow binding to ports 80/443
sudo setcap cap_net_bind_service=+ep boringproxy

# Start the gateway server
./boringproxy server \
  --db-dir ~/.boringproxy \
  --cert-dir ~/.boringproxy/certs \
  --acme-email your@email.com \
  --accept-ca-terms \
  --print-login
```

The server will:
1. Generate an admin token
2. Print a login URL
3. Start listening for client connections

Save the admin token and URL - you'll need them to connect clients.

## 2. Setting Up a Client

On your local machine where your service is running:

1. Build boringproxy the same way as the gateway:
```bash
git clone https://github.com/maietta/boringproxy
cd boringproxy
./scripts/generate_logo.sh
cd cmd/boringproxy
go build
```

2. Connect to your gateway server:
```bash
./boringproxy client \
  --server your-gateway-domain.com \
  --token YOUR_ADMIN_TOKEN \
  --client-name my-laptop \
  --user admin
```

3. Access the gateway's admin interface:
- Open the login URL from earlier
- Create a new tunnel pointing to your local service

Example: If you have a web server running on `localhost:8080`, create a tunnel:
- Domain: `myapp.your-gateway-domain.com`
- Local Port: `8080`

Your service will now be accessible at `https://myapp.your-gateway-domain.com`!

# Detailed Configuration

## Gateway Server Options

```bash
./boringproxy server [options]
  --db-dir DIR          Directory for database storage
  --cert-dir DIR        Directory for SSL certificates
  --acme-email EMAIL    Email for Let's Encrypt registration
  --accept-ca-terms     Accept Let's Encrypt terms
  --print-login         Print admin login URL
  --http-port PORT      HTTP port (default: 80)
  --https-port PORT     HTTPS port (default: 443)
  --allow-http         Allow unencrypted HTTP traffic
```

## Client Options

```bash
./boringproxy client [options]
  --server DOMAIN       Gateway server domain
  --token TOKEN        Admin token from gateway
  --client-name NAME   Unique name for this client
  --user USER         Username (usually 'admin')
```

# Development Setup

For local development and testing, you can run both gateway and client on the same machine:

1. Start the gateway in HTTP mode:
```bash
./boringproxy server \
  --db-dir ~/.boringproxy \
  --allow-http \
  --http-port 3000 \
  --https-port 3001 \
  --admin-domain localhost \
  --print-login
```

2. In another terminal, start the client:
```bash
./boringproxy client \
  --server localhost:3001 \
  --token YOUR_LOCAL_TOKEN \
  --client-name local-dev \
  --user admin
```

# Getting Help

If you run into problems running boringproxy, the best place to ask for help is
over at the [IndieBits][0] community, where we have a [dedicated section][1]
for boringproxy support. If you think you've found a bug, or want to discuss
development, please [open an issue][2].

[0]: https://forum.indiebits.io
[1]: https://forum.indiebits.io/c/boringproxy-support/9
[2]: https://github.com/maietta/boringproxy/issues
