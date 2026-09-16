package proxy

import (
	"encoding/json"
	"kiro-go/config"
	"kiro-go/logger"
	"net/http"
	"strings"
)

// Region switching for OAuth accounts.
//
// The Kiro data plane is selected by the account's profile ARN, whose region
// segment decides the q.{region}.amazonaws.com host used for generation. An
// account can legitimately own profiles in more than one region, but automatic
// resolution keeps the first ARN it finds and caches it forever, so operators
// had no way to move an existing account to another region.
//
// These endpoints expose the profiles the credential actually owns and let an
// operator pin one. Pinning sets Account.ProfileArnPinned so neither
// ListAvailableProfiles discovery nor a refresh-token response can revert it.
//
// API-key accounts are intentionally excluded: they route by Account.Region and
// have no IDE profile ARN.

// apiGetAccountProfiles GET /admin/api/accounts/{id}/profiles
// Probes every candidate data-plane region and returns the profiles owned by
// this credential, marking which one is currently active.
func (h *Handler) apiGetAccountProfiles(w http.ResponseWriter, r *http.Request, id string) {
	account, ok := h.lookupRegionSwitchAccount(w, id)
	if !ok {
		return
	}

	if err := h.ensureValidToken(account); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "Token refresh failed: " + err.Error()})
		return
	}

	profiles, err := DiscoverKiroProfilesContext(r.Context(), account)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	current := strings.TrimSpace(account.ProfileArn)
	items := make([]map[string]interface{}, 0, len(profiles))
	for _, profile := range profiles {
		items = append(items, map[string]interface{}{
			"arn":     profile.ARN,
			"name":    profile.Name,
			"region":  profile.Region,
			"current": profile.ARN == current,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"profiles":     items,
		"currentArn":   current,
		"activeRegion": kiroRegion(account),
		"pinned":       account.ProfileArnPinned,
	})
}

// apiSetAccountProfile POST /admin/api/accounts/{id}/profile
// Body: {"profileArn": "arn:aws:codewhisperer:eu-central-1:..."} pins a region.
// Body: {"reset": true} clears the pin and lets discovery choose again.
func (h *Handler) apiSetAccountProfile(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		ProfileARN string `json:"profileArn"`
		Reset      bool   `json:"reset"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	account, ok := h.lookupRegionSwitchAccount(w, id)
	if !ok {
		return
	}

	if req.Reset {
		if err := config.PinAccountProfileArn(id, ""); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		h.afterRegionChange(id)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "pinned": false})
		return
	}

	profileARN, _, valid := parseKiroProfileArn(req.ProfileARN)
	if !valid {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "profileArn is invalid"})
		return
	}

	// Only accept an ARN this credential actually owns. Without this check an
	// operator could point the account at an arbitrary account/region pair and
	// every later request would fail upstream with a confusing error.
	if err := h.ensureValidToken(account); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "Token refresh failed: " + err.Error()})
		return
	}
	owned, err := DiscoverKiroProfilesContext(r.Context(), account)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Unable to verify profileArn against Kiro profiles: " + err.Error(),
		})
		return
	}
	matched := false
	for _, profile := range owned {
		if profile.ARN == profileARN {
			matched = true
			break
		}
	}
	if !matched {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Selected Kiro profile is not available for this account",
		})
		return
	}

	if err := config.PinAccountProfileArn(id, profileARN); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	h.afterRegionChange(id)

	region := regionFromProfileArn(profileARN)
	logger.Infof("[Region] Account %s pinned to %s", accountEmailForLog(account), region)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"pinned":     true,
		"profileArn": profileARN,
		"region":     region,
	})
}

// lookupRegionSwitchAccount resolves an account that supports region switching,
// writing the HTTP error response itself when it cannot.
func (h *Handler) lookupRegionSwitchAccount(w http.ResponseWriter, id string) (*config.Account, bool) {
	accounts := config.GetAccounts()
	var account *config.Account
	for i := range accounts {
		if accounts[i].ID == id {
			account = &accounts[i]
			break
		}
	}
	if account == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Account not found"})
		return nil, false
	}
	if config.IsAPIKeyAccount(account) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "API key accounts do not use Kiro profiles; re-import the key with the desired region",
		})
		return nil, false
	}
	// Use the pool's live credential so discovery does not run with a token
	// that a concurrent refresh has already replaced.
	if latest := h.pool.GetByID(id); latest != nil {
		account.AccessToken = latest.AccessToken
		account.RefreshToken = latest.RefreshToken
		account.ExpiresAt = latest.ExpiresAt
	}
	return account, true
}

// afterRegionChange republishes the new profile ARN to the pool and drops the
// per-account model routing cache, whose contents are region specific.
func (h *Handler) afterRegionChange(id string) {
	h.pool.Reload()
	h.pool.SetModelList(id, nil)
}
