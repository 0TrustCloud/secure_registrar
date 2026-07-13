package secure_registrar

import "testing"

func TestValidatePrivateTLD_OpenNonICANN(t *testing.T) {
	allow := []string{"mesh", "tunnel", "factory", "eng", "corp-internal", "williwaw", "0trust", "defcon", "social", "mail", "search"}
	for _, tld := range allow {
		if err := ValidatePrivateTLD(tld); err != nil {
			t.Errorf("expected allow .%s: %v", tld, err)
		}
	}
}

func TestValidatePrivateTLD_RejectICANN(t *testing.T) {
	deny := []string{"com", "net", "org", "app", "dev", "cloud", "name", "io", "uk", "co", "google"}
	for _, tld := range deny {
		if err := ValidatePrivateTLD(tld); err == nil {
			t.Errorf("expected reject .%s", tld)
		}
	}
}

func TestValidatePrivateTLD_RejectSpecialUse(t *testing.T) {
	for _, tld := range []string{"localhost", "local", "onion", "invalid"} {
		if err := ValidatePrivateTLD(tld); err == nil {
			t.Errorf("expected reject special-use .%s", tld)
		}
	}
}

func TestValidatePrivateTLD_RejectMalformed(t *testing.T) {
	for _, tld := range []string{"", "foo.bar", "-bad", "bad-", "has_under"} {
		if err := ValidatePrivateTLD(tld); err == nil {
			t.Errorf("expected reject malformed %q", tld)
		}
	}
}

func TestIsICANNDelegatedTLD_TwoLetter(t *testing.T) {
	if !IsICANNDelegatedTLD("us") {
		t.Fatal("us is ccTLD")
	}
	if IsICANNDelegatedTLD("mesh") {
		t.Fatal("mesh is not ICANN")
	}
}
