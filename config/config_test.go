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

// TestLegacyStatsMigrateToUsEast1 covers the one-time backfill. Region-aware
// accounting was added after these counters had been accumulating, and all of
// that traffic was served by us-east-1, so existing totals are attributed there
// rather than being discarded or left unattributed.
func TestLegacyStatsMigrateToUsEast1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := map[string]interface{}{
		"password": "pw",
		"accounts": []map[string]interface{}{{
			"id":           "legacy-1",
			"authMethod":   "idc",
			"enabled":      true,
			"requestCount": 120,
			"totalTokens":  45000,
			"totalCredits": 12.5,
			"lastUsed":     1700000000,
		}},
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy config: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	if err := Init(path); err != nil {
		t.Fatalf("Init: %v", err)
	}

	account := GetAccounts()[0]
	bucket, ok := account.StatsByRegion[LegacyStatsRegion]
	if !ok {
		t.Fatalf("legacy usage was not attributed to %s: %+v",
			LegacyStatsRegion, account.StatsByRegion)
	}
	if bucket.RequestCount != 120 || bucket.TotalTokens != 45000 {
		t.Fatalf("migrated bucket = %+v, want 120 requests / 45000 tokens", bucket)
	}
	if bucket.TotalCredits < 12.49 || bucket.TotalCredits > 12.51 {
		t.Fatalf("migrated credits = %v, want 12.5", bucket.TotalCredits)
	}
	// Totals must be preserved, not moved.
	if account.RequestCount != 120 || account.TotalTokens != 45000 {
		t.Fatalf("totals altered by migration: %+v", account)
	}

	// The backfill must be idempotent: reloading must not double-count.
	if err := Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	again := GetAccounts()[0].StatsByRegion[LegacyStatsRegion]
	if again.RequestCount != 120 || again.TotalTokens != 45000 {
		t.Fatalf("migration is not idempotent: %+v", again)
	}
}

// TestMigrationSkipsAccountsWithoutUsage keeps fresh accounts free of an empty
// us-east-1 bucket they never used.
func TestMigrationSkipsAccountsWithoutUsage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw, err := json.Marshal(map[string]interface{}{
		"password": "pw",
		"accounts": []map[string]interface{}{{
			"id":         "fresh-1",
			"authMethod": "idc",
			"enabled":    true,
		}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := Init(path); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got := GetAccounts()[0].StatsByRegion; len(got) != 0 {
		t.Fatalf("unused account got a region bucket: %+v", got)
	}
}

// TestUpdateAccountStatsClonesRegionMap ensures the persisted breakdown does not
// alias the caller's map, so a later pool write cannot mutate stored config
// state without going through the lock.
func TestUpdateAccountStatsClonesRegionMap(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := AddAccount(Account{ID: "acct", AuthMethod: "idc", Enabled: true}); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	caller := map[string]RegionStats{
		"eu-central-1": {RequestCount: 2, TotalTokens: 100, TotalCredits: 1.0},
	}
	if err := UpdateAccountStats("acct", 2, 0, 100, 1.0, 1700000001, caller); err != nil {
		t.Fatalf("UpdateAccountStats: %v", err)
	}

	// Mutating the caller's map afterwards must not affect stored state.
	caller["eu-central-1"] = RegionStats{RequestCount: 999}
	caller["injected"] = RegionStats{RequestCount: 7}

	stored := GetAccounts()[0].StatsByRegion
	if stored["eu-central-1"].RequestCount != 2 {
		t.Fatalf("stored bucket aliased the caller map: %+v", stored)
	}
	if _, injected := stored["injected"]; injected {
		t.Fatalf("caller mutation leaked into stored state: %+v", stored)
	}
}

// TestAccumulateRegionStatsIsCopyOnWrite documents that the helper never mutates
// the map it is given, which is what makes concurrent pool snapshots safe.
func TestAccumulateRegionStatsIsCopyOnWrite(t *testing.T) {
	original := map[string]RegionStats{
		"us-east-1": {RequestCount: 1, TotalTokens: 10, TotalCredits: 0.5},
	}
	updated := AccumulateRegionStats(original, "us-east-1", 5, 0.25, 1700000002)

	if original["us-east-1"].TotalTokens != 10 {
		t.Fatalf("input map was mutated: %+v", original)
	}
	got := updated["us-east-1"]
	if got.RequestCount != 2 || got.TotalTokens != 15 {
		t.Fatalf("accumulated = %+v, want 2 requests / 15 tokens", got)
	}
	if got.LastUsed != 1700000002 {
		t.Fatalf("lastUsed = %d, want 1700000002", got.LastUsed)
	}

	// An empty region must leave the breakdown untouched. The helper returns the
	// input map as-is rather than nil, because callers assign the result back and
	// returning nil would silently erase an existing breakdown.
	unchanged := AccumulateRegionStats(original, "  ", 5, 0.25, 1)
	if len(unchanged) != 1 {
		t.Fatalf("empty region changed the bucket count: %+v", unchanged)
	}
	if unchanged["us-east-1"].RequestCount != 1 || unchanged["us-east-1"].TotalTokens != 10 {
		t.Fatalf("empty region altered the existing bucket: %+v", unchanged)
	}
	if _, blank := unchanged[""]; blank {
		t.Fatalf("empty region created a bucket: %+v", unchanged)
	}
}

// TestLoadMigratesLegacyStatsToUSEastOne covers the one-time backfill. Region
// accounting was added after these counters had been accumulating, and all of
// that traffic was served by us-east-1, so the existing totals belong there.
func TestLoadMigratesLegacyStatsToUSEastOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"password":"p","port":8080,"host":"0.0.0.0",
		"accounts":[
			{"id":"legacy","email":"legacy@example.com","authMethod":"idc","enabled":true,
			 "requestCount":12,"totalTokens":3400,"totalCredits":7.5,"lastUsed":1700000000},
			{"id":"fresh","email":"fresh@example.com","authMethod":"idc","enabled":true}
		]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if err := Init(path); err != nil {
		t.Fatalf("Init: %v", err)
	}

	accounts := GetAccounts()
	var legacy, fresh *Account
	for i := range accounts {
		switch accounts[i].ID {
		case "legacy":
			legacy = &accounts[i]
		case "fresh":
			fresh = &accounts[i]
		}
	}
	if legacy == nil || fresh == nil {
		t.Fatalf("expected both accounts, got %+v", accounts)
	}

	bucket, ok := legacy.StatsByRegion[LegacyStatsRegion]
	if !ok {
		t.Fatalf("legacy stats were not attributed to %s: %+v", LegacyStatsRegion, legacy.StatsByRegion)
	}
	if bucket.RequestCount != 12 || bucket.TotalTokens != 3400 || bucket.TotalCredits != 7.5 {
		t.Fatalf("migrated bucket = %+v, want the original totals", bucket)
	}
	if bucket.LastUsed != 1700000000 {
		t.Fatalf("migrated lastUsed = %d", bucket.LastUsed)
	}
	// Totals must stay untouched: the breakdown is additional, not a move.
	if legacy.RequestCount != 12 || legacy.TotalTokens != 3400 || legacy.TotalCredits != 7.5 {
		t.Fatalf("totals changed during migration: %+v", legacy)
	}
	// An account with no history gets no synthetic bucket.
	if len(fresh.StatsByRegion) != 0 {
		t.Fatalf("unused account got a region bucket: %+v", fresh.StatsByRegion)
	}

	// The backfill must be persisted, not recomputed on every load.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("persisted config is not valid JSON")
	}
	var onDisk Config
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, account := range onDisk.Accounts {
		if account.ID == "legacy" && len(account.StatsByRegion) == 0 {
			t.Fatal("migration was not saved to disk")
		}
	}
}

// TestLoadDoesNotRemigrateExistingBreakdown ensures the backfill never
// overwrites real per-region data on a later start.
func TestLoadDoesNotRemigrateExistingBreakdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"password":"p","port":8080,"host":"0.0.0.0",
		"accounts":[
			{"id":"mixed","email":"mixed@example.com","authMethod":"idc","enabled":true,
			 "requestCount":30,"totalTokens":900,"totalCredits":9,
			 "statsByRegion":{"eu-central-1":{"requestCount":30,"totalTokens":900,"totalCredits":9}}}
		]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if err := Init(path); err != nil {
		t.Fatalf("Init: %v", err)
	}

	accounts := GetAccounts()
	if len(accounts) != 1 {
		t.Fatalf("accounts = %d", len(accounts))
	}
	breakdown := accounts[0].StatsByRegion
	if len(breakdown) != 1 {
		t.Fatalf("breakdown = %+v, want only the original eu-central-1 bucket", breakdown)
	}
	if _, exists := breakdown[LegacyStatsRegion]; exists {
		t.Fatalf("migration invented a %s bucket: %+v", LegacyStatsRegion, breakdown)
	}
	if breakdown["eu-central-1"].RequestCount != 30 {
		t.Fatalf("existing bucket was modified: %+v", breakdown)
	}
}

func TestUpdateAccountStatsPersistsRegionBreakdown(t *testing.T) {
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := AddAccount(Account{
		ID: "acct", Email: "a@example.com", AuthMethod: "idc", Enabled: true,
	}); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	breakdown := map[string]RegionStats{
		"us-east-1":    {RequestCount: 2, TotalTokens: 100, TotalCredits: 1.5, LastUsed: 111},
		"eu-central-1": {RequestCount: 1, TotalTokens: 50, TotalCredits: 0.5, LastUsed: 222},
	}
	if err := UpdateAccountStats("acct", 3, 0, 150, 2.0, 222, breakdown); err != nil {
		t.Fatalf("UpdateAccountStats: %v", err)
	}

	stored := GetAccounts()[0]
	if stored.TotalTokens != 150 || stored.TotalCredits != 2.0 {
		t.Fatalf("totals = %+v", stored)
	}
	if len(stored.StatsByRegion) != 2 {
		t.Fatalf("breakdown = %+v", stored.StatsByRegion)
	}
	if stored.StatsByRegion["eu-central-1"].TotalTokens != 50 {
		t.Fatalf("eu bucket = %+v", stored.StatsByRegion["eu-central-1"])
	}

	// The stored map must be a clone: mutating the caller's map afterwards
	// must not leak into configuration state.
	breakdown["us-east-1"] = RegionStats{RequestCount: 999}
	if GetAccounts()[0].StatsByRegion["us-east-1"].RequestCount != 2 {
		t.Fatal("UpdateAccountStats stored the caller's map by reference")
	}
}
