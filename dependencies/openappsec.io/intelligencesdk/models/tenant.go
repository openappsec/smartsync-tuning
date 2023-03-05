package models

// TenantsList is the list of tenants
type TenantsList []string

// ReportedMultiTenants is the request body for authenticating multi tenants in the tenant inventory
type ReportedMultiTenants struct {
	Tenants TenantsList `json:"tenants"`
}

// TenantDescendants is the response from the "get tenant descendants" API
type TenantDescendants struct {
	Tenants TenantsList `json:"tenants"`
}

// TenantAncestors is the response from the "get tenant ancestor" API
type TenantAncestors struct {
	Tenants TenantsList `json:"tenants"`
}

// TenantAuthAndUnAuth is the lists of authorize and unauthorized tenants
type TenantAuthAndUnAuth struct {
	Authorized   TenantsList `json:"authorized"`
	Unauthorized TenantsList `json:"unauthorized"`
}

// MultiTenantsRes is the response body for authenticating multi tenants in the tenant inventory
type MultiTenantsRes struct {
	Tenants TenantAuthAndUnAuth `json:"tenants"`
}

// TenantsMap is the map of authorized tenants
type TenantsMap map[string]struct{}

// TenantEvent is the request body for a tenant event request
type TenantEvent struct {
	EventType string `json:"eventType"`
	TenantID  string `json:"tenantId"`
	Key       string `json:"-"`
}

const (
	// InitTenantEventType is the event type value for the init tenant event message
	InitTenantEventType = "initTenant"

	// DeleteTenantEventType is the event type value for the delete tenant event message
	DeleteTenantEventType = "deleteTenantPermanently"
)
