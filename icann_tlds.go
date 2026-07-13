package secure_registrar

import (
	"fmt"
	"strings"
	"unicode"
)

// intentionalPrivateOverlays are mesh product TLDs that MAY be registered even when
// the same string exists in the public ICANN root (split DNS intentionally answers
// them from the gTLD plane for clients pointed at 0Trust resolvers).
//
// All other ICANN-delegated labels are rejected. Any non-ICANN single label is allowed.
var intentionalPrivateOverlays = map[string]struct{}{
	"social": {}, // Williwaw product zone (.social also exists as ICANN gTLD)
	"mail":   {}, // product / common private use; keep if ever delegated publicly
	"search": {},
}

// IsICANNDelegatedTLD reports whether label is treated as public-root / ICANN space
// for the purpose of blocking accidental private registration.
// Intentional product overlays return false so they remain registerable.
func IsICANNDelegatedTLD(label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return false
	}
	if _, ok := intentionalPrivateOverlays[label]; ok {
		return false
	}
	// Two-letter labels are ccTLD space (assigned or reserved by IANA).
	if len(label) == 2 {
		a, b := label[0], label[1]
		if a >= 'a' && a <= 'z' && b >= 'a' && b <= 'z' {
			return true
		}
	}
	_, ok := icannMultiLetterTLDs[label]
	return ok
}

// ValidatePrivateTLD checks that tld may be registered as a private mesh extension:
// single LDH DNS label, not an unintended ICANN collision, not special-use reserved.
// Any non-ICANN TLD that passes label rules is allowed (open namespace).
func ValidatePrivateTLD(tld string) error {
	tld = strings.ToLower(strings.TrimSpace(tld))
	if tld == "" {
		return fmt.Errorf("tld is required")
	}
	if strings.Contains(tld, ".") {
		return fmt.Errorf("invalid TLD format: extension zones cannot contain dots")
	}
	if err := validateDNSLabel(tld); err != nil {
		return err
	}
	if IsICANNDelegatedTLD(tld) {
		return fmt.Errorf("tld .%s is ICANN/IANA delegated — private mesh TLDs must be non-ICANN (or an intentional product overlay)", tld)
	}
	if _, ok := specialUseTLDs[tld]; ok {
		return fmt.Errorf("tld .%s is reserved (special-use / local name space)", tld)
	}
	return nil
}

// IsIntentionalPrivateOverlay reports product TLDs allowed despite public-root collision.
func IsIntentionalPrivateOverlay(label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	_, ok := intentionalPrivateOverlays[label]
	return ok
}

func validateDNSLabel(label string) error {
	if len(label) < 1 || len(label) > 63 {
		return fmt.Errorf("invalid TLD length: must be 1–63 characters")
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("invalid TLD: cannot start or end with hyphen")
	}
	for _, r := range label {
		if r > unicode.MaxASCII {
			return fmt.Errorf("invalid TLD: non-ASCII labels are not supported in v1")
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return fmt.Errorf("invalid TLD: only LDH labels (letters, digits, hyphen) allowed")
	}
	return nil
}

// RFC 6761 / common local namespaces that MUST NOT be claimed as mesh TLDs.
var specialUseTLDs = map[string]struct{}{
	"localhost":   {},
	"local":       {},
	"invalid":     {},
	"onion":       {},
	"example":     {},
	"localdomain": {},
}

// icannMultiLetterTLDs denylists multi-letter public-root TLDs. Two-letter labels
// are handled in IsICANNDelegatedTLD. Keep product-safe non-ICANN names (mesh, tunnel, …)
// off this list. "social" is ICANN but allowlisted via intentionalPrivateOverlays.
var icannMultiLetterTLDs = map[string]struct{}{
	// Infrastructure / sponsored
	"arpa": {}, "gov": {}, "mil": {}, "edu": {}, "int": {},
	// Original / legacy gTLDs
	"com": {}, "net": {}, "org": {}, "info": {}, "biz": {}, "name": {}, "pro": {},
	"aero": {}, "asia": {}, "cat": {}, "coop": {}, "jobs": {}, "mobi": {},
	"museum": {}, "tel": {}, "travel": {}, "xxx": {}, "post": {},
	// High-traffic new gTLDs (collision would break mainstream Internet for DoH clients)
	"app": {}, "dev": {}, "page": {}, "new": {}, "how": {}, "soy": {},
	"cloud": {}, "online": {}, "site": {}, "website": {}, "space": {}, "tech": {},
	"store": {}, "shop": {}, "blog": {}, "news": {}, "media": {}, "email": {},
	"web": {}, "xyz": {}, "top": {}, "icu": {}, "club": {}, "vip": {},
	"win": {}, "bid": {}, "download": {}, "stream": {}, "live": {}, "life": {},
	"world": {}, "today": {}, "digital": {}, "network": {}, "systems": {},
	"company": {}, "business": {}, "solutions": {}, "services": {}, "agency": {},
	"center": {}, "global": {}, "international": {}, "group": {},
	"ltd": {}, "llc": {}, "inc": {}, "gmbh": {}, "limited": {},
	"security": {}, "protection": {}, "computer": {}, "software": {},
	"hosting": {}, "domains": {}, "dns": {}, "server": {}, "servers": {},
	"host": {}, "storage": {}, "data": {}, "database": {},
	"api": {}, "rest": {}, "json": {}, "xml": {},
	"nyc": {}, "london": {}, "berlin": {}, "paris": {}, "tokyo": {},
	"africa": {}, "lat": {}, "latino": {},
	"game": {}, "games": {}, "play": {}, "fun": {}, "lol": {},
	"music": {}, "band": {}, "video": {}, "film": {}, "movie": {}, "tube": {},
	"photo": {}, "photos": {}, "pics": {}, "gallery": {}, "art": {}, "design": {},
	"studio": {}, "fashion": {}, "style": {}, "luxury": {},
	"money": {}, "cash": {}, "finance": {}, "bank": {}, "insurance": {},
	"health": {}, "healthcare": {}, "clinic": {}, "dental": {}, "doctor": {},
	"law": {}, "lawyer": {}, "legal": {}, "accountant": {}, "tax": {},
	"school": {}, "university": {}, "college": {}, "education": {}, "academy": {},
	"church": {}, "faith": {}, "bible": {},
	"family": {}, "kids": {}, "baby": {}, "mom": {},
	"pet": {}, "dog": {},
	"car": {}, "cars": {}, "auto": {}, "autos": {}, "motorcycles": {},
	"house": {}, "homes": {}, "rent": {}, "rentals": {}, "property": {},
	"realtor": {}, "estate": {}, "land": {}, "farm": {},
	"build": {}, "builders": {}, "construction": {}, "contractors": {},
	"energy": {}, "green": {}, "eco": {}, "solar": {},
	"tools": {}, "equipment": {}, "supplies": {}, "parts": {},
	"exchange": {}, "market": {}, "markets": {}, "trading": {}, "forex": {},
	"crypto": {}, "bitcoin": {}, "nft": {},
	"ooo": {}, "cyou": {}, "buzz": {}, "click": {}, "link": {},
	"wow": {}, "zip": {}, "mov": {}, "sbs": {}, "cfd": {}, "bond": {},
	"quest": {}, "help": {}, "support": {}, "team": {}, "work": {}, "works": {},
	"careers": {}, "hire": {}, "recruitment": {},
	"press": {}, "report": {}, "reviews": {}, "feedback": {},
	"wiki": {}, "forum": {}, "community": {},
	// Brand TLDs (sample)
	"google": {}, "amazon": {}, "aws": {}, "azure": {}, "microsoft": {},
	"apple": {}, "ibm": {}, "oracle": {}, "cisco": {}, "nvidia": {},
	"github": {}, "youtube": {}, "gmail": {},
	// Explicit: social is ICANN gTLD but product overlay (see intentionalPrivateOverlays)
	"social": {},
}
