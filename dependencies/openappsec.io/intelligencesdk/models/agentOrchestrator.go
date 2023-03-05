package models

// NewAgentConfigRequest is the request body of the set new config API used to notify of an agent settings change (from agent orchestrator)
type NewAgentConfigRequest struct {
	ID            int    `json:"id"`
	PolicyVersion string `json:"policy_version"`
}

// NewAgentConfigResponse is the response body of the set new config API used to acknowledge an agent settings change (from agent orchestrator)
type NewAgentConfigResponse struct {
	ID           int    `json:"id"`
	Error        bool   `json:"error"`
	Finished     bool   `json:"finished"`
	ErrorMessage string `json:"error_message"`
}

// GetJWTResponse is the response of get jwt from agent orchestrator
type GetJWTResponse struct {
	Jwt        string `json:"token"`
	Expiration int    `json:"expiration"`
}
