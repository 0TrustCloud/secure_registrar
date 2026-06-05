package secure_registrar

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0TrustCloud/secure_dns"
	"github.com/0TrustCloud/ultimate_db"
)

// ==========================================
// CORE CONSTANTS & SCHEMAS
// ==========================================

const (
	RegistryPageID ultimate_db.PageID = 54
	ConfigPageID   ultimate_db.PageID = 55
)

type DomainMetadata struct {
	Domain       string    `json:"domain"`
	OwnerPub     string    `json:"owner_pub"`
	ParentDomain string    `json:"parent_domain"`
	RegisteredAt time.Time `json:"registered_at"`
}

type UIField struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Placeholder string `json:"placeholder"`
}

type UIButton struct {
	Label   string `json:"label"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
	OnClick string `json:"on_click"`
}

type UIConfig struct {
	BrandName    string    `json:"brand_name"`
	PrimaryColor string    `json:"primary_color"`
	Logo         string    `json:"logo"`
	Description  string    `json:"description"`
	FormAction   string    `json:"form_action"`
	Fields       []UIField `json:"fields"`
	Buttons      []UIButton`json:"buttons"`
}

func DefaultConfig() UIConfig {
	return UIConfig{
		BrandName:    "0TrustCloud Infrastructure",
		PrimaryColor: "#1d9bf0",
		Logo:         "???",
		Description:  "Verify your device passkey credentials to connect to the cluster overlay mesh.",
		FormAction:   "/auth/callback",
		Fields: []UIField{
			{ID: "username", Name: "username", Type: "text", Placeholder: "Phone, email, or username"},
		},
		Buttons: []UIButton{
			{Label: "Next", Type: "submit", Primary: true},
		},
	}
}

// ==========================================
// REGISTRAR GOVERNANCE ENGINE
// ==========================================

type RegistrarEngine struct {
	db  *ultimate_db.DB
	dns *secure_dns.SecureDNS
	mu  sync.RWMutex
}

func NewRegistrarEngine(database *ultimate_db.DB, dnsService *secure_dns.SecureDNS) *RegistrarEngine {
	return &RegistrarEngine{
		db:  database,
		dns: dnsService,
	}
}

func (re *RegistrarEngine) RegisterTLD(tld, adminPub string) error {
	tld = strings.TrimSpace(strings.ToLower(tld))
	if strings.Contains(tld, ".") {
		return fmt.Errorf("invalid TLD format: extension zones cannot contain dots")
	}
	return re.commitOwnership(tld, adminPub, "")
}

func (re *RegistrarEngine) RegisterRootDomain(domain, ownerPub string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	parts := strings.Split(domain, ".")
	if len(parts) != 2 {
		return fmt.Errorf("domain selection must be a root tier child directly under an active TLD")
	}

	if _, err := re.GetOwnership(parts[1]); err != nil {
		return fmt.Errorf("target TLD extension tier .%s is not configured on this network: %w", parts[1], err)
	}

	return re.commitOwnership(domain, ownerPub, parts[1])
}

func (re *RegistrarEngine) RegisterSubdomain(subdomain, ownerPub string) error {
	subdomain = strings.TrimSpace(strings.ToLower(subdomain))
	parts := strings.SplitN(subdomain, ".", 2)
	if len(parts) < 2 {
		return fmt.Errorf("malformed subdomain tree structure")
	}

	parentMeta, err := re.GetOwnership(parts[1])
	if err != nil {
		return fmt.Errorf("parent zone context hierarchy '%s' not found: %w", parts[1], err)
	}

	if parentMeta.OwnerPub != ownerPub {
		return fmt.Errorf("unauthorized: identity credentials do not match parent zone owner '%s'", parts[1])
	}

	return re.commitOwnership(subdomain, ownerPub, parts[1])
}

func (re *RegistrarEngine) MaintainResourceRecord(callerPub, domain, recordType, value string, ttl int) error {
	meta, err := re.GetOwnership(domain)
	if err != nil {
		return fmt.Errorf("cannot configure operational resource rows for an unassigned zone: %w", err)
	}

	if meta.OwnerPub != callerPub {
		return fmt.Errorf("access denied: configuration signature does not own namespace %s", domain)
	}

	return re.dns.RegisterDomain(domain, recordType, value, ttl)
}

func (re *RegistrarEngine) UpdateUIConfig(callerPub, domain string, cfg UIConfig) error {
	meta, err := re.GetOwnership(domain)
	if err != nil {
		return fmt.Errorf("target namespace context not found: %w", err)
	}

	if meta.OwnerPub != callerPub {
		return fmt.Errorf("access denied: security identifier does not own domain %s", domain)
	}

	rawBytes, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	txn := re.db.BeginTxn()
	// Writes to the uniform layout state key read by your bootstrap loader
	err = re.db.Write(ConfigPageID, txn, []byte("ui_settings"), rawBytes, "")
	re.db.CommitTxn(txn)
	return err
}

func (re *RegistrarEngine) GetOwnership(domain string) (*DomainMetadata, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	
	txn := re.db.BeginTxn()
	rawBytes, err := re.db.Read(RegistryPageID, txn, []byte("owner:"+domain))
	re.db.CommitTxn(txn)

	if err != nil || len(rawBytes) == 0 {
		return nil, fmt.Errorf("namespace identifier lease is unassigned")
	}

	var meta DomainMetadata
	if err := json.Unmarshal(rawBytes, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func (re *RegistrarEngine) commitOwnership(domain, ownerPub, parent string) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	if existing, err := re.GetOwnership(domain); err == nil {
		return fmt.Errorf("namespace collision: zone is already held by %s", existing.OwnerPub)
	}

	meta := DomainMetadata{
		Domain:       domain,
		OwnerPub:     ownerPub,
		ParentDomain: parent,
		RegisteredAt: time.Now(),
	}

	rawBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	txn := re.db.BeginTxn()
	err = re.db.Write(RegistryPageID, txn, []byte("owner:"+domain), rawBytes, "")
	re.db.CommitTxn(txn)
	return err
}

// ==========================================
// HTTP ROUTE EXPORTS & HANDLERS
// ==========================================

type RouteModule interface {
	Public(pattern string, handler http.HandlerFunc)
	Secure(pattern string, handler http.HandlerFunc)
}

type RegistrarHandler struct {
	Engine *RegistrarEngine
}

func MountRegistrarRoutes(module RouteModule, engine *RegistrarEngine) {
	h := &RegistrarHandler{Engine: engine}

	module.Public("GET /registry/lookup", h.HandleLookup)
	
	module.Secure("POST /registry/tld", h.HandleRegisterTLD)
	module.Secure("POST /registry/domain", h.HandleRegisterDomain)
	module.Secure("POST /registry/subdomain", h.HandleRegisterSubdomain)
	module.Secure("POST /registry/dns/record", h.HandleMaintainDNS)
	module.Secure("POST /registry/ui/layout", h.HandleSaveLayout)
}

func (h *RegistrarHandler) HandleLookup(w http.ResponseWriter, req *http.Request) {
	domain := req.URL.Query().Get("domain")
	meta, err := h.Engine.GetOwnership(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

func (h *RegistrarHandler) HandleRegisterTLD(w http.ResponseWriter, req *http.Request) {
	callerPub := req.Header.Get("X-Identity-Public-Key")
	tld := req.FormValue("tld")
	if callerPub == "" || tld == "" {
		http.Error(w, "Bad Request: Missing parameter data properties", http.StatusBadRequest)
		return
	}
	if err := h.Engine.RegisterTLD(tld, callerPub); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *RegistrarHandler) HandleRegisterDomain(w http.ResponseWriter, req *http.Request) {
	callerPub := req.Header.Get("X-Identity-Public-Key")
	domain := req.FormValue("domain")
	if callerPub == "" || domain == "" {
		http.Error(w, "Bad Request: Missing verification properties", http.StatusBadRequest)
		return
	}
	if err := h.Engine.RegisterRootDomain(domain, callerPub); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *RegistrarHandler) HandleRegisterSubdomain(w http.ResponseWriter, req *http.Request) {
	callerPub := req.Header.Get("X-Identity-Public-Key")
	subdomain := req.FormValue("subdomain")
	if callerPub == "" || subdomain == "" {
		http.Error(w, "Bad Request: Missing metadata parameters", http.StatusBadRequest)
		return
	}
	if err := h.Engine.RegisterSubdomain(subdomain, callerPub); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *RegistrarHandler) HandleMaintainDNS(w http.ResponseWriter, req *http.Request) {
	callerPub := req.Header.Get("X-Identity-Public-Key")
	domain := req.FormValue("domain")
	recType := req.FormValue("type")
	value := req.FormValue("value")
	ttlStr := req.FormValue("ttl")

	ttl, err := strconv.Atoi(ttlStr)
	if err != nil || callerPub == "" || domain == "" || recType == "" || value == "" {
		http.Error(w, "Malformed network packet parameters", http.StatusBadRequest)
		return
	}

	if err := h.Engine.MaintainResourceRecord(callerPub, domain, recType, value, ttl); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	_, _ = w.Write([]byte(`{"status":"DNS resource parameters signed and deployed"}`))
}

func (h *RegistrarHandler) HandleSaveLayout(w http.ResponseWriter, req *http.Request) {
	callerPub := req.Header.Get("X-Identity-Public-Key")
	domain := req.FormValue("domain")

	var incomingConfig UIConfig
	if err := json.NewDecoder(req.Body).Decode(&incomingConfig); err != nil {
		http.Error(w, "Invalid structural JSON formatting schema", http.StatusBadRequest)
		return
	}

	if err := h.Engine.UpdateUIConfig(callerPub, domain, incomingConfig); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	_, _ = w.Write([]byte(`{"status":"Dynamic branding properties saved successfully"}`))
}
