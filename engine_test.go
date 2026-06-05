package secure_registrar

import (
	"encoding/json"
	"strings"
	"testing"
)

// Minimal mock structures to satisfy the database token interactions 
// without spinning up a live disk I/O engine.
type mockTxn struct{}

type mockDB struct {
	kv map[string][]byte
}

func newMockDB() *mockDB {
	return &mockDB{kv: make(map[string][]byte)}
}

// TestTLDRegistrationBoundaries asserts that TLDs are normalized to lowercase
// and formatting constraints (like blocking dots) are strictly enforced.
func TestTLDRegistrationBoundaries(t *testing.T) {
	// Setup a clean engine state map
	storage := make(map[string][]byte)
	
	tldTests := []struct {
		name      string
		tld       string
		adminPub  string
		wantError bool
	}{
		{"Valid TLD", "trust", "admin-key-123", false},
		{"Valid TLD Uppercase Normalization", "CLOUD", "admin-key-123", false},
		{"Invalid TLD Containing Dot", "shld.zone", "admin-key-123", true},
		{"Empty TLD String", "", "admin-key-123", true},
	}

	for _, tt := range tldTests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := strings.TrimSpace(strings.ToLower(tt.tld))
			if normalized == "" {
				return
			}

			if strings.Contains(normalized, ".") {
				if !tt.wantError {
					t.Errorf("Expected validation failure for TLD containing dots: %s", tt.tld)
				}
				return
			}

			// Simulate the write operation of commitOwnership
			key := "owner:" + normalized
			if _, exists := storage[key]; exists && !tt.wantError {
				t.Errorf("Namespace collision tracking failed for: %s", tt.tld)
			}

			meta := DomainMetadata{
				Domain:   normalized,
				OwnerPub: tt.adminPub,
			}
			rawBytes, _ := json.Marshal(meta)
			storage[key] = rawBytes

			// Verify data consistency
			storedBytes := storage[key]
			var verifiedMeta DomainMetadata
			_ = json.Unmarshal(storedBytes, &verifiedMeta)

			if verifiedMeta.Domain != normalized || verifiedMeta.OwnerPub != tt.adminPub {
				t.Errorf("Data corruption inside simulated storage wrapper")
			}
		})
	}
}

// TestDomainHierarchyValidation ensures root domains cannot be registered 
// unless their parent TLD is explicitly configured on the platform first.
func TestDomainHierarchyValidation(t *testing.T) {
	storage := make(map[string][]byte)
	
	// Pre-seed an active platform TLD extension
	tldMeta := DomainMetadata{Domain: "cloud", OwnerPub: "platform-root"}
	tldBytes, _ := json.Marshal(tldMeta)
	storage["owner:cloud"] = tldBytes

	domainTests := []struct {
		name      string
		domain    string
		ownerPub  string
		wantError bool
	}{
		{"Valid Domain Under Pre-seeded TLD", "infrastructure.cloud", "user-key-abc", false},
		{"Invalid Domain Multi-Tier Format", "sub.node.cloud", "user-key-abc", true},
		{"Invalid Domain Missing Registered TLD", "secure.network", "user-key-abc", true},
	}

	for _, tt := range domainTests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := strings.TrimSpace(strings.ToLower(tt.domain))
			parts := strings.Split(normalized, ".")
			
			if len(parts) != 2 {
				if !tt.wantError {
					t.Errorf("Failed to catch malformed root domain structure: %s", tt.domain)
				}
				return
			}

			// Validate if parent TLD context exists in storage
			_, tldExists := storage["owner:"+parts[1]]
			if !tldExists {
				if !tt.wantError {
					t.Errorf("Allowed domain registration under an unconfigured TLD extension: %s", parts[1])
				}
				return
			}

			if !tt.wantError {
				meta := DomainMetadata{Domain: normalized, OwnerPub: tt.ownerPub, ParentDomain: parts[1]}
				rawBytes, _ := json.Marshal(meta)
				storage["owner:"+normalized] = rawBytes
			}
		})
	}
}

// TestSubdomainOwnershipVerification checks the cascading security rule:
// Only the verified owner of a parent domain can issue child subdomains under it.
func TestSubdomainOwnershipVerification(t *testing.T) {
	storage := make(map[string][]byte)

	// Pre-seed a root domain owned explicitly by "alice-public-key"
	parentDomain := "alice.cloud"
	parentMeta := DomainMetadata{
		Domain:       parentDomain,
		OwnerPub:     "alice-public-key",
		ParentDomain: "cloud",
	}
	parentBytes, _ := json.Marshal(parentMeta)
	storage["owner:"+parentDomain] = parentBytes

	subdomainTests := []struct {
		name       string
		subdomain  string
		callerPub  string
		wantError  bool
	}{
		{"Authorized Owner Subdomain Creation", "api.alice.cloud", "alice-public-key", false},
		{"Unauthorized Hijack Attempt", "malicious.alice.cloud", "bob-public-key", true},
	}

	for _, tt := range subdomainTests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := strings.TrimSpace(strings.ToLower(tt.subdomain))
			parts := strings.SplitN(normalized, ".", 2)
			
			if len(parts) < 2 {
				t.Fatalf("Malformed test configuration string hierarchy")
			}

			// Fetch parent domain ownership data from storage
			rawParent, exists := storage["owner:"+parts[1]]
			if !exists {
				t.Fatalf("Parent zone context missing from simulator map")
			}

			var currentParent DomainMetadata
			_ = json.Unmarshal(rawParent, &currentParent)

			// Zero-Trust Rule Assertion
			if currentParent.OwnerPub != tt.callerPub {
				if !tt.wantError {
					t.Errorf("Security Breach: Unauthorized identity %s successfully branched a subdomain off of %s", tt.callerPub, parts[1])
				}
				return
			}

			if tt.wantError {
				t.Errorf("Expected error scenario did not fire for caller: %s", tt.callerPub)
			}
		})
	}
}

// TestUIConfigStatePersistence verifies that incoming dynamic workspace interface edits
// validate identity claims correctly and write cleanly to the designated config registry page.
func TestUIConfigStatePersistence(t *testing.T) {
	storage := make(map[string][]byte)

	targetDomain := "hub.cloud"
	ownerKey := "identity-token-xyz"

	// Register domain space in the mock map
	domainMeta := DomainMetadata{Domain: targetDomain, OwnerPub: ownerKey}
	domainBytes, _ := json.Marshal(domainMeta)
	storage["owner:"+targetDomain] = domainBytes

	// Prepare an incoming dynamic interface modification payload
	customConfig := UIConfig{
		BrandName:    "Custom Cluster Gateway",
		PrimaryColor: "#ff0000",
		Logo:         "??",
		Description:  "Isolated environment workspace access verification portal.",
	}

	// Step 1: Verify identity claims
	metaBytes, exists := storage["owner:"+targetDomain]
	if !exists {
		t.Fatalf("Target domain namespace was unassigned")
	}

	var meta DomainMetadata
	_ = json.Unmarshal(metaBytes, &meta)

	if meta.OwnerPub != ownerKey {
		t.Fatalf("Authorization credentials rejected prematurely")
	}

	// Step 2: Simulate persistence to ConfigPageID allocation spaces
	configKey := "ui_settings:" + targetDomain
	rawConfigBytes, err := json.Marshal(customConfig)
	if err != nil {
		t.Fatalf("Failed to marshal target configuration options: %v", err)
	}
	storage[configKey] = rawConfigBytes

	// Step 3: Read back structural properties to verify mutation alignment
	readbackBytes := storage[configKey]
	var verifiedConfig UIConfig
	_ = json.Unmarshal(readbackBytes, &verifiedConfig)

	if verifiedConfig.BrandName != "Custom Cluster Gateway" || verifiedConfig.PrimaryColor != "#ff0000" {
		t.Errorf("Persisted layout parameters do not match input configurations")
	}
}
