package tunnels

import (
	"embed"
	"encoding/base64"

	//"encoding/json"
	"fmt"
	"html/template"
	"io"
	"maps"
	"net/http"

	qrcode "github.com/skip2/go-qrcode"

	//"net/url"
	//"os"
	"strings"
	"sync"
	"time"
)

//go:embed logo.png templates
var fs embed.FS

// WebUIHandler handles all web interface operations
type WebUIHandler struct {
	config          *Config
	db              *Database
	api             *Api
	auth            *Auth
	headHtml        template.HTML
	tmpl            *template.Template
	pendingRequests map[string]chan ReqResult
	mutex           *sync.Mutex
}

// ReqResult represents the result of an asynchronous request
type ReqResult struct {
	err         error
	redirectUrl string
}

type ConfirmData struct {
	Head       template.HTML
	Message    string
	ConfirmUrl string
	CancelUrl  string
}

type LoadingData struct {
	Head      template.HTML
	TargetUrl string
}

type AlertData struct {
	Head        template.HTML
	Message     string
	RedirectUrl string
}

type LoginData struct {
	Head template.HTML
}

func NewWebUiHandler(config *Config, db *Database, api *Api, auth *Auth) *WebUIHandler {
	return &WebUIHandler{
		config:          config,
		db:              db,
		api:             api,
		auth:            auth,
		pendingRequests: make(map[string]chan ReqResult),
		mutex:           &sync.Mutex{},
	}
}

func (h *WebUIHandler) handleWebUIRequest(w http.ResponseWriter, r *http.Request) {
	var err error
	h.tmpl, err = template.ParseFS(fs, "templates/*.tmpl")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse templates: %v", err), http.StatusInternalServerError)
		return
	}

	token, err := extractToken("access_token", r)
	if err != nil {
		h.sendLoginPage(w, http.StatusUnauthorized)
		return
	}

	tokenData, exists := h.db.GetTokenData(token)
	if !exists {
		h.sendLoginPage(w, http.StatusForbidden)
		return
	}

	if tokenData.Client != "" {
		http.Error(w, "This token is limited to a specific client and cannot be used for the web UI", http.StatusForbidden)
		return
	}

	user, exists := h.db.GetUser(tokenData.Owner)
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	tunnels := h.api.GetTunnels(tokenData)

	for domain, tun := range tunnels {
		tunnels[domain] = tun
	}

	switch r.URL.Path {
	case "/login":
		h.handleLogin(w, r)
	case "/users":
		h.handleUsers(w, r, tokenData, user)

	case "/confirm-delete-user":
		h.confirmDeleteUser(w, r)
	case "/delete-user":
		h.deleteUser(w, r, tokenData)
	case "/logo.png":

		logoPngBytes, err := fs.ReadFile("logo.png")
		if err != nil {
			w.WriteHeader(500)
			h.alertDialog(w, err.Error(), "/")
			return
		}

		w.Header()["Content-Type"] = []string{"image/png"}
		w.Header()["Cache-Control"] = []string{"max-age=86400"}

		w.Write(logoPngBytes)

	case "/":
		http.Redirect(w, r, "/tunnels", 303)
	case "/tunnels":
		h.handleTunnels(w, r, tokenData, user)
	case "/confirm-delete-tunnel":

		r.ParseForm()

		if len(r.Form["domain"]) != 1 {
			w.WriteHeader(400)
			w.Write([]byte("Invalid domain parameter"))
			return
		}
		domain := r.Form["domain"][0]

		data := &ConfirmData{
			Head:       h.headHtml,
			Message:    fmt.Sprintf("Are you sure you want to delete %s?", domain),
			ConfirmUrl: fmt.Sprintf("/delete-tunnel?domain=%s", domain),
			CancelUrl:  "/tunnels",
		}

		h.tmpl.ExecuteTemplate(w, "confirm.tmpl", data)

	case "/edit-tunnel":
		r.ParseForm()

		domain := r.Form.Get("domain")

		var users map[string]User

		// TODO: handle security checks in api
		if user.IsAdmin {
			users = h.db.GetUsers()
		} else {
			users = make(map[string]User)
			users[tokenData.Owner] = user
		}

		templateData := struct {
			Domain string
			UserId string
			User   User
			Users  map[string]User
		}{
			Domain: domain,
			UserId: tokenData.Owner,
			User:   user,
			Users:  users,
		}

		err = h.tmpl.ExecuteTemplate(w, "edit_tunnel.tmpl", templateData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

	case "/delete-tunnel":

		r.ParseForm()

		err := h.api.DeleteTunnel(tokenData, r.Form)
		if err != nil {
			w.WriteHeader(400)
			h.alertDialog(w, err.Error(), "/tunnels")
			return
		}

		http.Redirect(w, r, "/tunnels", 303)

	case "/tunnel-private-key":

		r.ParseForm()

		tun, err := h.api.GetTunnel(tokenData, r.Form)
		if err != nil {
			w.WriteHeader(400)
			h.alertDialog(w, err.Error(), "/tunnels")
			return
		}

		w.Header().Set("Content-Disposition", "attachment; filename=id_rsa")
		io.WriteString(w, tun.TunnelPrivateKey)

	case "/add-token-client":
		r.ParseForm()

		owner := r.Form.Get("owner")

		addTokenUser, _ := h.db.GetUser(owner)

		templateData := struct {
			Owner string
			User  User
		}{
			Owner: owner,
			User:  addTokenUser,
		}

		err := h.tmpl.ExecuteTemplate(w, "add_token_client.tmpl", templateData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	case "/tokens":
		h.handleTokens(w, r, user, tokenData)
	case "/clients":
		h.handleClients(w, r, user, tokenData)
	case "/confirm-delete-token":
		h.confirmDeleteToken(w, r)
	case "/delete-token":
		h.deleteToken(w, r, tokenData)
	case "/confirm-delete-client":
		h.confirmDeleteClient(w, r)
	case "/delete-client":
		h.deleteClient(w, r, tokenData)
	case "/confirm-logout":

		data := &ConfirmData{
			Head:       h.headHtml,
			Message:    "Are you sure you want to log out?",
			ConfirmUrl: "/logout",
			CancelUrl:  "/",
		}

		err := h.tmpl.ExecuteTemplate(w, "confirm.tmpl", data)
		if err != nil {
			w.WriteHeader(500)
			h.alertDialog(w, err.Error(), "/")
			return
		}

	case "/logout":
		cookie := &http.Cookie{
			Name:     "access_token",
			Value:    "",
			Secure:   true,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/tunnels", http.StatusSeeOther)
	case "/loading":
		h.handleLoading(w, r)
	case "/alert":

		r.ParseForm()

		message := r.Form.Get("message")

		h.alertDialog(w, message, "/")
	case "/takingnames":
		h.handleTakingNames(w, r)
	default:
		if strings.HasPrefix(r.URL.Path, "/tunnels/") {

			r.ParseForm()

			parts := strings.Split(r.URL.Path, "/")

			if len(parts) != 3 {
				w.WriteHeader(400)
				h.alertDialog(w, "Invalid path", "/tunnels")
				return
			}

			domain := parts[2]

			r.Form.Set("domain", domain)

			tunnel, err := h.api.GetTunnel(tokenData, r.Form)
			if err != nil {
				w.WriteHeader(400)
				h.alertDialog(w, err.Error(), "/tunnels")
				return
			}

			templateData := struct {
				User   User
				Tunnel Tunnel
			}{
				User:   user,
				Tunnel: tunnel,
			}

			err = h.tmpl.ExecuteTemplate(w, "tunnel.tmpl", templateData)
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}
		} else {
			w.WriteHeader(404)
			h.alertDialog(w, "Unknown page "+r.URL.Path, "/tunnels")
			return
		}
	}
}

func (h *WebUIHandler) handleTokens(w http.ResponseWriter, r *http.Request, user User, tokenData TokenData) {

	r.ParseForm()

	switch r.Method {
	case "GET":
		var tokens map[string]TokenData
		var users map[string]User

		// TODO: handle security checks in api
		if user.IsAdmin {
			tokens = h.db.GetTokens()
			users = h.db.GetUsers()
		} else {
			tokens = make(map[string]TokenData)

			for token, td := range h.db.GetTokens() {
				if tokenData.Owner == td.Owner {
					tokens[token] = td
				}
			}

			users = make(map[string]User)
			users[tokenData.Owner] = user
		}

		qrCodes := make(map[string]template.URL)
		for token := range tokens {
			adminDomain := h.db.GetAdminDomain()
			loginUrl := fmt.Sprintf("https://%s/login?access_token=%s", adminDomain, token)

			var png []byte
			png, err := qrcode.Encode(loginUrl, qrcode.Medium, 256)
			if err != nil {
				w.WriteHeader(500)
				h.alertDialog(w, err.Error(), "/tokens")
				return
			}

			data := base64.StdEncoding.EncodeToString(png)
			qrCodes[token] = template.URL("data:image/png;base64," + data)
		}

		templateData := struct {
			Tokens  map[string]TokenData
			User    User
			Users   map[string]User
			QrCodes map[string]template.URL
		}{
			Tokens:  tokens,
			User:    user,
			Users:   users,
			QrCodes: qrCodes,
		}

		err := h.tmpl.ExecuteTemplate(w, "tokens.tmpl", templateData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	case "POST":
		_, err := h.api.CreateToken(tokenData, r.Form)
		if err != nil {
			w.WriteHeader(500)
			h.alertDialog(w, err.Error(), "/tokens")
			return
		}

		http.Redirect(w, r, "/tokens", http.StatusSeeOther)
	default:
		w.WriteHeader(405)
		h.alertDialog(w, "Invalid method for tokens", "/tokens")
		return
	}
}

func (h *WebUIHandler) handleClients(w http.ResponseWriter, r *http.Request, user User, tokenData TokenData) {

	r.ParseForm()

	switch r.Method {
	case "GET":
		var users map[string]User

		// TODO: handle security checks in api
		if user.IsAdmin {
			users = h.db.GetUsers()
		} else {
			user, _ := h.db.GetUser(tokenData.Owner)
			users = make(map[string]User)
			users[tokenData.Owner] = user
		}

		clients := make(map[string]DbClient)
		for _, user := range users {
			maps.Copy(clients, user.Clients)
		}

		templateData := struct {
			User    User
			Users   map[string]User
			Clients map[string]DbClient
		}{
			User:    user,
			Users:   users,
			Clients: clients,
		}

		err := h.tmpl.ExecuteTemplate(w, "clients.tmpl", templateData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	case "POST":

		owner := r.Form.Get("owner")
		clientName := r.Form.Get("client-name")

		err := h.api.SetClient(tokenData, r.Form, owner, clientName)
		if err != nil {
			w.WriteHeader(500)
			h.alertDialog(w, err.Error(), "/clients")
			return
		}
		http.Redirect(w, r, "/clients", http.StatusSeeOther)
	default:
		w.WriteHeader(405)
		h.alertDialog(w, "Invalid method for tokens", "/tokens")
		return
	}
}
func (h *WebUIHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()

	tokenList, ok := r.Form["access_token"]
	if !ok {
		http.Error(w, "Token required for login", http.StatusBadRequest)
		return
	}

	token := tokenList[0]
	if h.auth.Authorized(token) {
		cookie := &http.Cookie{
			Name:     "access_token",
			Value:    token,
			Secure:   true,
			HttpOnly: true,
			MaxAge:   86400 * 365,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/tunnels", http.StatusSeeOther)
	} else {
		h.sendLoginPage(w, http.StatusForbidden)
	}
}

func (h *WebUIHandler) handleTunnels(w http.ResponseWriter, r *http.Request, tokenData TokenData, user User) {

	switch r.Method {
	case "POST":
		h.handleCreateTunnel(w, r, tokenData)
	case "GET":
		tunnels := h.api.GetTunnels(tokenData)

		templateData := struct {
			User    User
			Tunnels map[string]Tunnel
		}{
			User:    user,
			Tunnels: tunnels,
		}

		err := h.tmpl.ExecuteTemplate(w, "tunnels.tmpl", templateData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	default:
		w.WriteHeader(405)
		w.Write([]byte("Invalid method for /tunnels"))
		return
	}
}

func (h *WebUIHandler) handleCreateTunnel(w http.ResponseWriter, r *http.Request, tokenData TokenData) {

	pendingId, err := genRandomCode(16)
	if err != nil {
		w.WriteHeader(400)
		h.alertDialog(w, err.Error(), "/tunnels")
	}

	doneSignal := make(chan ReqResult)
	h.mutex.Lock()
	h.pendingRequests[pendingId] = doneSignal
	h.mutex.Unlock()

	go func() {

		r.ParseForm()

		_, err := h.api.CreateTunnel(tokenData, r.Form)

		doneSignal <- ReqResult{err, "/tunnels"}
	}()

	timeout := make(chan bool, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		timeout <- true
	}()

	select {
	case <-timeout:
		url := fmt.Sprintf("/loading?id=%s", pendingId)

		data := &LoadingData{
			Head:      h.headHtml,
			TargetUrl: url,
		}

		h.tmpl.ExecuteTemplate(w, "loading.tmpl", data)
		if err != nil {
			w.WriteHeader(500)
			h.alertDialog(w, err.Error(), "/tunnels")
			return
		}

	case result := <-doneSignal:
		if result.err != nil {
			w.WriteHeader(400)
			h.alertDialog(w, result.err.Error(), result.redirectUrl)
			return
		}

		http.Redirect(w, r, result.redirectUrl, http.StatusSeeOther)
	}
}

func (h *WebUIHandler) sendLoginPage(w http.ResponseWriter, code int) {
	loginData := LoginData{
		Head: h.headHtml,
	}

	w.WriteHeader(code)
	err := h.tmpl.ExecuteTemplate(w, "login.tmpl", loginData)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}
}

func (h *WebUIHandler) handleUsers(w http.ResponseWriter, r *http.Request, tokenData TokenData, user User) {

	r.ParseForm()

	switch r.Method {
	case "GET":
		var users map[string]User

		// TODO: handle security checks in api
		if user.IsAdmin {
			users = h.db.GetUsers()
		} else {
			users = make(map[string]User)
			users[tokenData.Owner] = user
		}

		templateData := struct {
			User  User
			Users map[string]User
		}{
			User:  user,
			Users: users,
		}

		err := h.tmpl.ExecuteTemplate(w, "users.tmpl", templateData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	case "POST":
		err := h.api.CreateUser(tokenData, r.Form)
		if err != nil {
			w.WriteHeader(500)
			h.alertDialog(w, err.Error(), "/users")
			return
		}

		http.Redirect(w, r, "/users", http.StatusSeeOther)
	default:
		w.WriteHeader(405)
		h.alertDialog(w, "Invalid method for users", "/users")
	}
}

func (h *WebUIHandler) confirmDeleteUser(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	if len(r.Form["username"]) != 1 {
		w.WriteHeader(400)
		w.Write([]byte("Invalid username parameter"))
		return
	}
	username := r.Form["username"][0]

	data := &ConfirmData{
		Head:       h.headHtml,
		Message:    fmt.Sprintf("Are you sure you want to delete user %s?", username),
		ConfirmUrl: fmt.Sprintf("/delete-user?username=%s", username),
		CancelUrl:  "/users",
	}

	err := h.tmpl.ExecuteTemplate(w, "confirm.tmpl", data)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}
}

func (h *WebUIHandler) deleteUser(w http.ResponseWriter, r *http.Request, tokenData TokenData) {

	r.ParseForm()

	err := h.api.DeleteUser(tokenData, r.Form)
	if err != nil {
		w.WriteHeader(500)
		h.alertDialog(w, err.Error(), "/users")
		return
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (h *WebUIHandler) confirmDeleteToken(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	if len(r.Form["token"]) != 1 {
		w.WriteHeader(400)
		w.Write([]byte("Invalid token parameter"))
		return
	}
	token := r.Form["token"][0]

	data := &ConfirmData{
		Head:       h.headHtml,
		Message:    fmt.Sprintf("Are you sure you want to delete token %s?", token),
		ConfirmUrl: fmt.Sprintf("/delete-token?token=%s", token),
		CancelUrl:  "/tokens",
	}

	err := h.tmpl.ExecuteTemplate(w, "confirm.tmpl", data)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}
}
func (h *WebUIHandler) deleteToken(w http.ResponseWriter, r *http.Request, tokenData TokenData) {

	r.ParseForm()
	err := h.api.DeleteToken(tokenData, r.Form)
	if err != nil {
		w.WriteHeader(500)
		h.alertDialog(w, err.Error(), "/tokens")
		return
	}

	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (h *WebUIHandler) confirmDeleteClient(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	owner := r.Form.Get("owner")
	clientName := r.Form.Get("client-name")

	data := &ConfirmData{
		Head:       h.headHtml,
		Message:    fmt.Sprintf("Are you sure you want to delete client %s for user %s?", clientName, owner),
		ConfirmUrl: fmt.Sprintf("/delete-client?owner=%s&client-name=%s", owner, clientName),
		CancelUrl:  "/clients",
	}

	err := h.tmpl.ExecuteTemplate(w, "confirm.tmpl", data)
	if err != nil {
		w.WriteHeader(500)
		h.alertDialog(w, err.Error(), "/clients")
		return
	}
}
func (h *WebUIHandler) deleteClient(w http.ResponseWriter, r *http.Request, tokenData TokenData) {

	r.ParseForm()

	owner := r.Form.Get("owner")
	clientName := r.Form.Get("client-name")

	err := h.api.DeleteClient(tokenData, owner, clientName)
	if err != nil {
		w.WriteHeader(500)
		h.alertDialog(w, err.Error(), "/clients")
		return
	}

	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

func (h *WebUIHandler) alertDialog(w http.ResponseWriter, message, redirectUrl string) error {
	err := h.tmpl.ExecuteTemplate(w, "alert.tmpl", &AlertData{
		Head:        h.headHtml,
		Message:     message,
		RedirectUrl: redirectUrl,
	})

	if err != nil {
		return err
	}

	return nil
}

func (h *WebUIHandler) handleLoading(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	pendingId := r.Form.Get("id")
	if pendingId == "" {
		http.Error(w, "Missing id parameter", http.StatusBadRequest)
		return
	}

	h.mutex.Lock()
	doneSignal, exists := h.pendingRequests[pendingId]
	if !exists {
		h.mutex.Unlock()
		http.Error(w, "Invalid or expired request id", http.StatusBadRequest)
		return
	}
	delete(h.pendingRequests, pendingId)
	h.mutex.Unlock()

	result := <-doneSignal
	if result.err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.alertDialog(w, result.err.Error(), result.redirectUrl); err != nil {
			http.Error(w, "Failed to render alert dialog", http.StatusInternalServerError)
		}
		return
	}

	http.Redirect(w, r, result.redirectUrl, http.StatusSeeOther)
}

func (h *WebUIHandler) handleTakingNames(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		link, err := h.config.DNSClient.BootstrapLink()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get bootstrap link: %v", err), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, link, http.StatusFound)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
