package secure_registrar

import "testing"

func TestPlatformLockBlocksGlueRecords(t *testing.T) {
	meta := &DomainMetadata{
		Domain:     "defcon.chat",
		OwnerPub:   "platform-mesh-pub",
		LockPolicy: LockPolicyPlatform,
	}
	re := &RegistrarEngine{}
	if err := re.assertDNSChangeAllowed(meta, "NS"); err == nil {
		t.Fatal("expected NS change to be blocked on platform-locked zone")
	}
	if err := re.assertDNSChangeAllowed(meta, "DS"); err == nil {
		t.Fatal("expected DS change to be blocked on platform-locked zone")
	}
	if err := re.assertDNSChangeAllowed(meta, "A"); err != nil {
		t.Fatalf("expected A record change to remain allowed, got %v", err)
	}
	if err := re.assertDNSChangeAllowed(meta, "TXT"); err != nil {
		t.Fatalf("expected TXT record change to remain allowed, got %v", err)
	}
}

func TestTransferOwnershipAlwaysDisabled(t *testing.T) {
	re := &RegistrarEngine{}
	if err := re.TransferOwnership("defcon.chat", "alice", "bob"); err != ErrTransferDisabled {
		t.Fatalf("expected ErrTransferDisabled, got %v", err)
	}
}

func TestDomainMetadataPlatformLock(t *testing.T) {
	meta := DomainMetadata{LockPolicy: LockPolicyPlatform}
	if !meta.hasPlatformLock() {
		t.Fatal("expected platform lock")
	}
	meta.LockPolicy = ""
	if meta.hasPlatformLock() {
		t.Fatal("expected no lock on empty policy")
	}
}