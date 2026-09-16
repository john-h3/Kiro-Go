package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"kiro-go/config"
	accountpool "kiro-go/pool"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	regionSwitchUSProfile = "arn:aws:codewhisperer:us-east-1:123456789012:profile/us-profile"
	regionSwitchEUProfile = "arn:aws:codewhisperer:eu-central-1:123456789012:profile/eu-profile"
)

func newRegionSwitchHandler(t *testing.T) *Handler {
	t.Helper()
	if err := config.Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	p := accountpool.GetPool()
	p.Reload()
	return &Handler{pool: p}
}

// installRegionProfileTransport serves ListAvailableProfiles per data-plane
// host so discovery sees one profile in us-east-1 and one in eu-central-1.
func installRegionProfileTransport(t *testing.T, hostProfiles map[string]string) *int {
	t.Helper()
	calls := 0
	client := &http.Client{
		Timeout: time.Second,
		Transport: handlerMicrosoftRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path != "/ListAvailableProfiles" {
				return nil, fmt.Errorf("unexpected request: %s %s", request.Method, request.URL)
			}
			calls++
			arn, ok := hostProfiles[request.URL.Hostname()]
			if !ok {
				return nil, fmt.Errorf("unexpected host %q", request.URL.Hostname())
			}
			return handlerMicrosoftJSONResponse(request, http.StatusOK, map[string]interface{}{
				"profiles": []map[string]string{{"arn": arn, "profileName": arn}},
			}), nil
		}),
	}
	previous := kiroRestHttpStore.Load()
	kiroRestHttpStore.Store(client)
	t.Cleanup(func() { kiroRestHttpStore.Store(previous) })
	return &calls
}

func addRegionSwitchAccount(t *testing.T, h *Handler, account config.Account) {
	t.Helper()
	if err := config.AddAccount(account); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	h.pool.Reload()
}

func oauthRegionAccount() config.Account {
	return config.Account{
		ID:           "acct-region-1",
		Email:        "region@example.com",
		AccessToken:  "at-valid",
		RefreshToken: "rt-valid",
		AuthMethod:   "social",
		Provider:     "BuilderId",
		Region:       "us-east-1",
		ProfileArn:   regionSwitchUSProfile,
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		Enabled:      true,
	}
}

func getProfiles(t *testing.T, h *Handler, id string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	recorder := httptest.NewRecorder()
	h.apiGetAccountProfiles(
		recorder,
		httptest.NewRequest(http.MethodGet, "/accounts/"+id+"/profiles", nil),
		id,
	)
	var body map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body
}

func setProfile(t *testing.T, h *Handler, id string, payload map[string]interface{}) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	recorder := httptest.NewRecorder()
	h.apiSetAccountProfile(
		recorder,
		httptest.NewRequest(http.MethodPost, "/accounts/"+id+"/profile", strings.NewReader(string(raw))),
		id,
	)
	var body map[string]interface{}
	json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body
}

func reloadAccount(t *testing.T, id string) config.Account {
	t.Helper()
	for _, a := range config.GetAccounts() {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("account %s not found", id)
	return config.Account{}
}

func TestGetAccountProfilesListsBothRegionsAndMarksCurrent(t *testing.T) {
	h := newRegionSwitchHandler(t)
	addRegionSwitchAccount(t, h, oauthRegionAccount())
	installRegionProfileTransport(t, map[string]string{
		"codewhisperer.us-east-1.amazonaws.com": regionSwitchUSProfile,
		"q.eu-central-1.amazonaws.com":          regionSwitchEUProfile,
	})

	recorder, body := getProfiles(t, h, "acct-region-1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	profiles, _ := body["profiles"].([]interface{})
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d (%s)", len(profiles), recorder.Body.String())
	}
	regions := map[string]bool{}
	current := ""
	for _, entry := range profiles {
		profile := entry.(map[string]interface{})
		regions[profile["region"].(string)] = true
		if profile["current"].(bool) {
			current = profile["arn"].(string)
		}
	}
	if !regions["us-east-1"] || !regions["eu-central-1"] {
		t.Fatalf("expected both data-plane regions, got %v", regions)
	}
	if current != regionSwitchUSProfile {
		t.Fatalf("current profile = %q, want %q", current, regionSwitchUSProfile)
	}
	if body["activeRegion"] != "us-east-1" {
		t.Fatalf("activeRegion = %v", body["activeRegion"])
	}
}

func TestSetAccountProfileSwitchesRegionAndPins(t *testing.T) {
	h := newRegionSwitchHandler(t)
	addRegionSwitchAccount(t, h, oauthRegionAccount())
	installRegionProfileTransport(t, map[string]string{
		"codewhisperer.us-east-1.amazonaws.com": regionSwitchUSProfile,
		"q.eu-central-1.amazonaws.com":          regionSwitchEUProfile,
	})

	recorder, body := setProfile(t, h, "acct-region-1", map[string]interface{}{
		"profileArn": regionSwitchEUProfile,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if body["region"] != "eu-central-1" {
		t.Fatalf("region = %v", body["region"])
	}

	stored := reloadAccount(t, "acct-region-1")
	if stored.ProfileArn != regionSwitchEUProfile {
		t.Fatalf("stored profileArn = %q", stored.ProfileArn)
	}
	if !stored.ProfileArnPinned {
		t.Fatal("expected ProfileArnPinned to be set")
	}
	// The data plane must now resolve to the newly chosen region.
	if got := kiroRegion(&stored); got != "eu-central-1" {
		t.Fatalf("kiroRegion = %q, want eu-central-1", got)
	}
	endpoint := regionalizeURL(kiroRestAPIBase+"/GetUserInfo", &stored)
	if !strings.Contains(endpoint, "q.eu-central-1.amazonaws.com") {
		t.Fatalf("endpoint not regionalized: %s", endpoint)
	}
}

func TestSetAccountProfileRejectsProfileNotOwned(t *testing.T) {
	h := newRegionSwitchHandler(t)
	addRegionSwitchAccount(t, h, oauthRegionAccount())
	installRegionProfileTransport(t, map[string]string{
		"codewhisperer.us-east-1.amazonaws.com": regionSwitchUSProfile,
		"q.eu-central-1.amazonaws.com":          regionSwitchEUProfile,
	})

	foreign := "arn:aws:codewhisperer:ap-southeast-2:999999999999:profile/not-mine"
	recorder, _ := setProfile(t, h, "acct-region-1", map[string]interface{}{"profileArn": foreign})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	stored := reloadAccount(t, "acct-region-1")
	if stored.ProfileArn != regionSwitchUSProfile || stored.ProfileArnPinned {
		t.Fatalf("account changed unexpectedly: %+v", stored)
	}
}

func TestSetAccountProfileRejectsMalformedArn(t *testing.T) {
	h := newRegionSwitchHandler(t)
	addRegionSwitchAccount(t, h, oauthRegionAccount())

	recorder, _ := setProfile(t, h, "acct-region-1", map[string]interface{}{
		"profileArn": "arn:aws:codewhisperer:evil.example.com:1:profile/x",
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if stored := reloadAccount(t, "acct-region-1"); stored.ProfileArnPinned {
		t.Fatal("malformed ARN must not pin the account")
	}
}

func TestSetAccountProfileResetClearsPin(t *testing.T) {
	h := newRegionSwitchHandler(t)
	account := oauthRegionAccount()
	account.ProfileArn = regionSwitchEUProfile
	account.ProfileArnPinned = true
	addRegionSwitchAccount(t, h, account)

	recorder, body := setProfile(t, h, "acct-region-1", map[string]interface{}{"reset": true})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if body["pinned"] != false {
		t.Fatalf("pinned = %v, want false", body["pinned"])
	}
	stored := reloadAccount(t, "acct-region-1")
	if stored.ProfileArnPinned || stored.ProfileArn != "" {
		t.Fatalf("reset should clear pin and ARN, got %+v", stored)
	}
}

func TestRegionEndpointsRejectAPIKeyAccounts(t *testing.T) {
	h := newRegionSwitchHandler(t)
	addRegionSwitchAccount(t, h, config.Account{
		ID:         "acct-apikey",
		Email:      "api@example.com",
		KiroApiKey: "ksk_key",
		AuthMethod: "api_key",
		Region:     "us-east-1",
		Enabled:    true,
	})

	if recorder, _ := getProfiles(t, h, "acct-apikey"); recorder.Code != http.StatusBadRequest {
		t.Fatalf("GET status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	recorder, _ := setProfile(t, h, "acct-apikey", map[string]interface{}{
		"profileArn": regionSwitchEUProfile,
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("POST status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRegionEndpointsReturnNotFoundForUnknownAccount(t *testing.T) {
	h := newRegionSwitchHandler(t)
	if recorder, _ := getProfiles(t, h, "missing"); recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d", recorder.Code)
	}
}

// A pinned region must survive a token refresh that reports the account's
// home-region profile, which is what previously reverted manual choices.
func TestPinnedRegionSurvivesRefreshReportedProfileArn(t *testing.T) {
	h := newRegionSwitchHandler(t)
	addRegionSwitchAccount(t, h, oauthRegionAccount())
	installRegionProfileTransport(t, map[string]string{
		"codewhisperer.us-east-1.amazonaws.com": regionSwitchUSProfile,
		"q.eu-central-1.amazonaws.com":          regionSwitchEUProfile,
	})

	if recorder, _ := setProfile(t, h, "acct-region-1", map[string]interface{}{
		"profileArn": regionSwitchEUProfile,
	}); recorder.Code != http.StatusOK {
		t.Fatalf("switch failed: %s", recorder.Body.String())
	}

	// Simulate the refresh path publishing the upstream us-east-1 ARN.
	if err := config.UpdateAccountCredentialState(
		"acct-region-1",
		"at-rotated",
		"rt-rotated",
		time.Now().Add(time.Hour).Unix(),
		regionSwitchUSProfile,
	); err != nil {
		t.Fatalf("UpdateAccountCredentialState: %v", err)
	}

	stored := reloadAccount(t, "acct-region-1")
	if stored.ProfileArn != regionSwitchEUProfile {
		t.Fatalf("refresh reverted pinned profile to %q", stored.ProfileArn)
	}
	if stored.AccessToken != "at-rotated" {
		t.Fatalf("token rotation was lost: %q", stored.AccessToken)
	}
}

// TestListProfilesSendsBodyUpstreamAccepts locks the request shape that the
// real ListAvailableProfiles API accepts. The endpoint rejects any unexpected
// member with HTTP 400 REQUEST_BODY_INVALID, so the first page must be a bare
// {} and a continuation must carry only a non-empty nextToken. Sending
// maxResults made profile discovery fail against every live region.
func TestListProfilesSendsBodyUpstreamAccepts(t *testing.T) {
	if err := config.Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("config.Init: %v", err)
	}

	var bodies []map[string]interface{}
	kiroRestHttpStore.Store(&http.Client{
		Transport: handlerMicrosoftRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(request.Body)
			var decoded map[string]interface{}
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("request body is not JSON: %q", raw)
			}
			bodies = append(bodies, decoded)

			if decoded["nextToken"] == "page-2" {
				return handlerMicrosoftJSONResponse(request, http.StatusOK, map[string]interface{}{
					"profiles": []map[string]string{{
						"arn":         "arn:aws:codewhisperer:us-east-1:123456789012:profile/two",
						"profileName": "Two",
					}},
				}), nil
			}
			return handlerMicrosoftJSONResponse(request, http.StatusOK, map[string]interface{}{
				"profiles": []map[string]string{{
					"arn":         "arn:aws:codewhisperer:us-east-1:123456789012:profile/one",
					"profileName": "One",
				}},
				"nextToken": "page-2",
			}), nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	profiles, err := listKiroProfilesInRegion(&config.Account{
		AccessToken: "token",
		AuthMethod:  "idc",
		Region:      "us-east-1",
	}, "us-east-1")
	if err != nil {
		t.Fatalf("list profiles: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("profiles = %d, want 2 across pages", len(profiles))
	}
	if len(bodies) != 2 {
		t.Fatalf("request count = %d, want 2", len(bodies))
	}

	// First page: strictly empty. Any member here is a 400 upstream.
	if len(bodies[0]) != 0 {
		t.Fatalf("first page body = %v, want {}", bodies[0])
	}
	// Continuation: nextToken only.
	if len(bodies[1]) != 1 || bodies[1]["nextToken"] != "page-2" {
		t.Fatalf("second page body = %v, want only nextToken=page-2", bodies[1])
	}
	for i, body := range bodies {
		if _, present := body["maxResults"]; present {
			t.Fatalf("page %d sent maxResults, which upstream rejects: %v", i, body)
		}
	}
}

// TestRefreshAccountRepublishesUsageToPool covers the single-account refresh
// endpoint. Switching region can move an account onto a data plane with its own
// separate quota, so a refresh that brings it back under limit must make it
// routable immediately instead of waiting for an unrelated pool write.
func TestRefreshAccountRepublishesUsageToPool(t *testing.T) {
	h := newRegionSwitchHandler(t)
	const accountID = "quota-1"

	// Persisted as over quota, which excludes it from the pool.
	if err := config.AddAccount(config.Account{
		ID:           accountID,
		Email:        "quota@example.com",
		AuthMethod:   "idc",
		Region:       "us-east-1",
		AccessToken:  "token",
		RefreshToken: "refresh",
		ProfileArn:   "arn:aws:codewhisperer:us-east-1:123456789012:profile/AAAAAAAAAA",
		UsageCurrent: 10246,
		UsageLimit:   10000,
		Enabled:      true,
	}); err != nil {
		t.Fatalf("add account: %v", err)
	}
	h.pool.Reload()
	if got := h.pool.AvailableCount(); got != 0 {
		t.Fatalf("available before refresh = %d, want 0 (over quota)", got)
	}

	// The refreshed region reports usage under its own limit.
	kiroRestHttpStore.Store(&http.Client{
		Transport: handlerMicrosoftRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return handlerMicrosoftJSONResponse(request, http.StatusOK, map[string]interface{}{
				"userInfo": map[string]string{
					"email":  "quota@example.com",
					"userId": "user-1",
				},
				"subscriptionInfo": map[string]string{
					"subscriptionTitle": "KIRO PRO",
					"type":              "Q_DEVELOPER_STANDALONE_PRO",
				},
				"usageBreakdownList": []map[string]interface{}{{
					"resourceType": "CREDIT",
					"currentUsage": 277,
					"usageLimit":   1000,
				}},
			}), nil
		}),
	})
	t.Cleanup(func() { InitKiroHttpClient("") })

	recorder := httptest.NewRecorder()
	h.apiRefreshAccount(
		recorder,
		httptest.NewRequest(http.MethodPost, "/accounts/"+accountID+"/refresh", nil),
		accountID,
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	if got := h.pool.AvailableCount(); got != 1 {
		t.Fatalf("available after refresh = %d, want 1; pool kept the stale over-quota snapshot", got)
	}
}
