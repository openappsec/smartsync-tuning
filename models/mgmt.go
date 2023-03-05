package models

//TenantsOverrides has a map of the matches in a tenant's overrides
type TenantsOverrides struct {
	Matches map[string][]OverrideData
}

// OverrideData stores the data of an override of a specific EventType
type OverrideData struct {
	MatchValue string
	Decision   string
}
