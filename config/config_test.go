package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeAPIKeyAccountPipeRegionAndMachineId(t *testing.T) {
	account := Account{
		KiroApiKey: " ksk_test_key|eu-central-1 ",
		AuthMethod: "API KEY",
	}
	if err := NormalizeAPIKeyAccount(&account); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if account.KiroApiKey != "ksk_test_key" {
		t.Fatalf("key = %q", account.KiroApiKey)
	}
	if account.AccessToken != "ksk_test_key" {
		t.Fatalf("accessToken should mirror api key, got %q", account.AccessToken)
	}
	if account.AuthMethod != "api_key" {
		t.Fatalf("authMethod = %q", account.AuthMethod)
	}
	if account.Region != "eu-central-1" {
		t.Fatalf("region = %q", account.Region)
	}
	if account.RefreshToken != "" || account.ProfileArn != "" || account.ExpiresAt != 0 {
		t.Fatalf("oauth fields should be cleared: %+v", account)
	}
	wantMachine := MachineIdFromAPIKey("ksk_test_key")
	if account.MachineId != wantMachine {
		t.Fatalf("machineId = %q, want %q", account.MachineId, wantMachine)
	}
	if !IsAPIKeyAccount(&account) {
		t.Fatal("expected IsAPIKeyAccount true")
	}
}

func TestAddAccountRejectsDuplicateAPIKey(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	first := Account{ID: "api-1", KiroApiKey: "ksk_dup", AuthMethod: "api_key", Enabled: true}
	if err := AddAccount(first); err != nil {
		t.Fatalf("add first: %v", err)
	}
	second := Account{ID: "api-2", KiroApiKey: "ksk_dup", AuthMethod: "api_key", Enabled: true}
	if err := AddAccount(second); err != ErrDuplicateAPIKey {
		t.Fatalf("expected ErrDuplicateAPIKey, got %v", err)
	}
}

func TestSplitKiroAPIKeyAndRegionValidation(t *testing.T) {
	key, region, err := SplitKiroAPIKeyAndRegion("ksk_abc|us-east-1")
	if err != nil || key != "ksk_abc" || region != "us-east-1" {
		t.Fatalf("got key=%q region=%q err=%v", key, region, err)
	}
	if _, _, err := SplitKiroAPIKeyAndRegion("ksk_abc|us-east-1|extra"); err == nil {
		t.Fatal("expected multi-pipe error")
	}
	if _, _, err := SplitKiroAPIKeyAndRegion("|us-east-1"); err == nil {
		t.Fatal("expected empty key error")
	}
}

func TestUpdateSettingsPatchPreservesOmittedAPIKeyFields(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := UpdateSettings("proxy-api-key", true, "admin-password"); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	if err := UpdateSettingsPatch(nil, nil, "new-admin-password"); err != nil {
		t.Fatalf("patch settings: %v", err)
	}

	if got := GetApiKey(); got != "proxy-api-key" {
		t.Fatalf("expected API key to be preserved, got %q", got)
	}
	if !IsApiKeyRequired() {
		t.Fatalf("expected requireApiKey to stay enabled")
	}
	if got := GetPassword(); got != "new-admin-password" {
		t.Fatalf("expected password to update, got %q", got)
	}
}

func TestUpdateSettingsPatchCanExplicitlyDisableAPIKey(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := UpdateSettings("proxy-api-key", true, "admin-password"); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	emptyKey := ""
	requireAPIKey := false
	if err := UpdateSettingsPatch(&emptyKey, &requireAPIKey, ""); err != nil {
		t.Fatalf("patch settings: %v", err)
	}

	if got := GetApiKey(); got != "" {
		t.Fatalf("expected API key to be cleared, got %q", got)
	}
	if IsApiKeyRequired() {
		t.Fatalf("expected requireApiKey to be disabled")
	}
	if got := GetPassword(); got != "admin-password" {
		t.Fatalf("expected password to be preserved, got %q", got)
	}
}

func TestUpdateAccountStaleSnapshotPreservesCredentialRotation(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	account := Account{
		ID:            "rotation-account",
		AccessToken:   "access-1",
		RefreshToken:  "refresh-1",
		ClientID:      "client",
		AuthMethod:    "external_idp",
		Region:        "us-east-1",
		ExpiresAt:     100,
		ProfileArn:    "arn:aws:codewhisperer:us-east-1:123456789012:profile/one",
		TokenEndpoint: "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
		IssuerURL:     "https://login.microsoftonline.com/tenant/v2.0",
		Scopes:        "scope-one",
		Enabled:       true,
	}
	if err := AddAccount(account); err != nil {
		t.Fatalf("add account: %v", err)
	}
	stale := GetAccounts()[0]

	const rotatedProfile = "arn:aws:codewhisperer:eu-central-1:123456789012:profile/two"
	if err := UpdateAccountCredentialState(
		account.ID,
		"access-2",
		"refresh-2",
		200,
		rotatedProfile,
	); err != nil {
		t.Fatalf("rotate credential: %v", err)
	}

	stale.Enabled = false
	stale.BanStatus = "BANNED"
	stale.BanReason = "stale status update"
	if err := UpdateAccount(account.ID, stale); err != nil {
		t.Fatalf("apply stale status snapshot: %v", err)
	}

	got := GetAccounts()[0]
	if got.AccessToken != "access-2" ||
		got.RefreshToken != "refresh-2" ||
		got.ExpiresAt != 200 ||
		got.ProfileArn != rotatedProfile {
		t.Fatalf("stale status update reverted credential state: %+v", got)
	}
	if got.RefreshTokenFingerprint != RefreshTokenFingerprint("refresh-1") {
		t.Fatalf("original refresh token fingerprint = %q", got.RefreshTokenFingerprint)
	}
	if got.Enabled || got.BanStatus != "BANNED" || got.BanReason != "stale status update" {
		t.Fatalf("status fields were not applied: %+v", got)
	}
}

// TestAccountAllowOverageMigration verifies that a config.json from before the
// upstream-Overages-switch refactor (which carried `allowOverage: true` per
// account) is migrated into OverageStatus="ENABLED" on first load, and that
// the legacy field is cleared so future saves don't re-emit it.
func TestAccountAllowOverageMigration(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.json")

	seed := map[string]interface{}{
		"password":      "p",
		"port":          8080,
		"host":          "0.0.0.0",
		"requireApiKey": false,
		"accounts": []map[string]interface{}{
			{"id": "acc-allow", "enabled": true, "allowOverage": true},
			{"id": "acc-deny", "enabled": true, "allowOverage": false},
			{"id": "acc-already-set", "enabled": true, "allowOverage": true, "overageStatus": "DISABLED"},
		},
	}
	raw, err := json.MarshalIndent(seed, "", "  ")
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(cfgFile, raw, 0600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	if err := Init(cfgFile); err != nil {
		t.Fatalf("init: %v", err)
	}

	accounts := GetAccounts()
	byID := map[string]Account{}
	for _, a := range accounts {
		byID[a.ID] = a
	}

	if got := byID["acc-allow"].OverageStatus; got != "ENABLED" {
		t.Fatalf("expected acc-allow to migrate to OverageStatus=ENABLED, got %q", got)
	}
	if byID["acc-allow"].LegacyAllowOverage {
		t.Fatalf("expected legacy allowOverage to be cleared after migration")
	}
	if got := byID["acc-deny"].OverageStatus; got != "" {
		t.Fatalf("expected acc-deny to keep empty OverageStatus, got %q", got)
	}
	// Pre-set OverageStatus must win over the legacy field.
	if got := byID["acc-already-set"].OverageStatus; got != "DISABLED" {
		t.Fatalf("expected acc-already-set OverageStatus to be preserved, got %q", got)
	}
	if byID["acc-already-set"].LegacyAllowOverage {
		t.Fatalf("expected legacy field to still be cleared on acc-already-set")
	}

	// Re-read the file and confirm legacy field is gone (so it doesn't drift
	// back in on later saves).
	on_disk, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var reloaded struct {
		Accounts []map[string]interface{} `json:"accounts"`
	}
	if err := json.Unmarshal(on_disk, &reloaded); err != nil {
		t.Fatalf("decode reload: %v", err)
	}
	for _, a := range reloaded.Accounts {
		if _, ok := a["allowOverage"]; ok {
			t.Fatalf("expected allowOverage to be omitted from persisted file, got %+v", a)
		}
	}
}

// --- region switching (pinned profile ARN) ---

const (
	testUSProfileArn = "arn:aws:codewhisperer:us-east-1:123456789012:profile/ABCDEFGHIJ"
	testEUProfileArn = "arn:aws:codewhisperer:eu-central-1:123456789012:profile/KLMNOPQRST"
)

func TestPinAccountProfileArnSetsAndClearsPin(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := AddAccount(Account{
		ID:         "acc-1",
		AuthMethod: "social",
		Region:     "us-east-1",
		ProfileArn: testUSProfileArn,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("add account: %v", err)
	}

	if err := PinAccountProfileArn("acc-1", testEUProfileArn); err != nil {
		t.Fatalf("pin: %v", err)
	}
	got := GetAccounts()[0]
	if got.ProfileArn != testEUProfileArn || !got.ProfileArnPinned {
		t.Fatalf("after pin: arn=%q pinned=%v", got.ProfileArn, got.ProfileArnPinned)
	}

	// Clearing the pin re-enables automatic discovery.
	if err := PinAccountProfileArn("acc-1", ""); err != nil {
		t.Fatalf("clear pin: %v", err)
	}
	got = GetAccounts()[0]
	if got.ProfileArn != "" || got.ProfileArnPinned {
		t.Fatalf("after clear: arn=%q pinned=%v", got.ProfileArn, got.ProfileArnPinned)
	}
}

func TestPinAccountProfileArnMissingAccount(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := PinAccountProfileArn("nope", testEUProfileArn); err != ErrAccountNotFound {
		t.Fatalf("expected ErrAccountNotFound, got %v", err)
	}
}

// A pinned region must survive a token refresh that reports the account's
// home-region profile, otherwise the switch silently reverts.
func TestUpdateAccountCredentialStateKeepsPinnedProfileArn(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := AddAccount(Account{
		ID:           "acc-1",
		AuthMethod:   "social",
		RefreshToken: "rt-1",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("add account: %v", err)
	}
	if err := PinAccountProfileArn("acc-1", testEUProfileArn); err != nil {
		t.Fatalf("pin: %v", err)
	}

	if err := UpdateAccountCredentialState("acc-1", "at-2", "rt-2", 111, testUSProfileArn); err != nil {
		t.Fatalf("update credential state: %v", err)
	}

	got := GetAccounts()[0]
	if got.ProfileArn != testEUProfileArn {
		t.Fatalf("pinned ARN was overwritten by refresh: %q", got.ProfileArn)
	}
	// The credential fields themselves must still be applied.
	if got.AccessToken != "at-2" || got.RefreshToken != "rt-2" || got.ExpiresAt != 111 {
		t.Fatalf("credential fields not updated: %+v", got)
	}
}

func TestUpdateAccountCredentialStateAppliesProfileArnWhenNotPinned(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := AddAccount(Account{
		ID:           "acc-1",
		AuthMethod:   "social",
		RefreshToken: "rt-1",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("add account: %v", err)
	}
	if err := UpdateAccountCredentialState("acc-1", "at-2", "rt-2", 111, testUSProfileArn); err != nil {
		t.Fatalf("update credential state: %v", err)
	}
	if got := GetAccounts()[0]; got.ProfileArn != testUSProfileArn {
		t.Fatalf("unpinned ARN should follow refresh, got %q", got.ProfileArn)
	}
}

func TestUpdateAccountProfileArnDoesNotOverwritePin(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := AddAccount(Account{ID: "acc-1", AuthMethod: "social", Enabled: true}); err != nil {
		t.Fatalf("add account: %v", err)
	}
	if err := PinAccountProfileArn("acc-1", testEUProfileArn); err != nil {
		t.Fatalf("pin: %v", err)
	}
	// Automatic discovery caching must be a no-op while pinned.
	if err := UpdateAccountProfileArn("acc-1", testUSProfileArn); err != nil {
		t.Fatalf("discovery cache: %v", err)
	}
	if got := GetAccounts()[0]; got.ProfileArn != testEUProfileArn {
		t.Fatalf("discovery overwrote pinned ARN: %q", got.ProfileArn)
	}
}

// UpdateAccount is the admin/status write path; it must not drop the pin flag.
func TestUpdateAccountPreservesProfileArnPin(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := AddAccount(Account{ID: "acc-1", AuthMethod: "social", Enabled: true}); err != nil {
		t.Fatalf("add account: %v", err)
	}
	if err := PinAccountProfileArn("acc-1", testEUProfileArn); err != nil {
		t.Fatalf("pin: %v", err)
	}

	stale := GetAccounts()[0]
	stale.ProfileArn = testUSProfileArn
	stale.ProfileArnPinned = false
	stale.Nickname = "renamed"
	if err := UpdateAccount("acc-1", stale); err != nil {
		t.Fatalf("update account: %v", err)
	}

	got := GetAccounts()[0]
	if got.Nickname != "renamed" {
		t.Fatalf("nickname not applied: %q", got.Nickname)
	}
	if got.ProfileArn != testEUProfileArn || !got.ProfileArnPinned {
		t.Fatalf("pin not preserved: arn=%q pinned=%v", got.ProfileArn, got.ProfileArnPinned)
	}
}

func TestPinnedProfileArnSurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Init(path); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if err := AddAccount(Account{ID: "acc-1", AuthMethod: "social", Enabled: true}); err != nil {
		t.Fatalf("add account: %v", err)
	}
	if err := PinAccountProfileArn("acc-1", testEUProfileArn); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if err := Init(path); err != nil {
		t.Fatalf("re-init config: %v", err)
	}
	if got := GetAccounts()[0]; got.ProfileArn != testEUProfileArn || !got.ProfileArnPinned {
		t.Fatalf("pin lost across reload: arn=%q pinned=%v", got.ProfileArn, got.ProfileArnPinned)
	}
}
