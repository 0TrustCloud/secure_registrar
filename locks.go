package secure_registrar

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Lock policy labels stored on DomainMetadata.LockPolicy.
const (
	LockPolicyPlatform = "platform" // no ownership transfer; NS/DS glue immutable via API
)

var (
	ErrTransferDisabled = fmt.Errorf("domain transfers are disabled on this registry")
	ErrGlueLocked       = fmt.Errorf("NS/DS glue records are locked for this zone")

)

func normalizeLockPolicy(policy string) string {
	return strings.TrimSpace(strings.ToLower(policy))
}

func isGlueRecordType(recordType string) bool {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case "NS", "DS":
		return true
	default:
		return false
	}
}

func (meta *DomainMetadata) hasPlatformLock() bool {
	if meta == nil {
		return false
	}
	return normalizeLockPolicy(meta.LockPolicy) == LockPolicyPlatform
}

// LockPlatformZone marks a zone as platform-operated: ownership cannot transfer and
// NS/DS records cannot be changed through MaintainResourceRecord (bootstrap paths
// write glue directly via secure_dns).
func (re *RegistrarEngine) LockPlatformZone(domain string) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	meta, err := re.GetOwnership(domain)
	if err != nil {
		return err
	}
	if meta.hasPlatformLock() {
		return nil
	}
	meta.LockPolicy = LockPolicyPlatform
	return re.persistMetadata(*meta)
}

// TransferOwnership is intentionally unsupported — registry leases are permanent.
func (re *RegistrarEngine) TransferOwnership(_, _, _ string) error {
	return ErrTransferDisabled
}

func (re *RegistrarEngine) assertDNSChangeAllowed(meta *DomainMetadata, recordType string) error {
	if meta == nil {
		return nil
	}
	if meta.hasPlatformLock() && isGlueRecordType(recordType) {
		return fmt.Errorf("%w: %s", ErrGlueLocked, meta.Domain)
	}
	return nil
}

func (re *RegistrarEngine) persistMetadata(meta DomainMetadata) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	rawBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	txn := re.db.BeginTxn()
	err = re.db.Write(RegistryPageID, txn, []byte("owner:"+meta.Domain), rawBytes, "")
	re.db.CommitTxn(txn)
	return err
}