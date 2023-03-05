package models

// json schemas - general
const (
	QueryAssetsSchemaName                       = "QueryAssets"
	QueryIntelSchemaName                        = "QueryIntelligence"
	ReportAssetsGenericSchemaName               = "ReportAssetsGeneric"
	SetNewConfigFromAgentOrchestratorSchemaName = "SetNewConfigurationFromAgentOrchestrator"
	ExternalSourceRegistrationSchemaName        = "ExternalSourceRegistration"
)

// json schemas - legacy
const (
	ReportAssetsSchemaName = "ReportAssets"
	PatchAssetSchemaName   = "PatchAsset"
	PutAssetSchemaName     = "PutAsset"
)

// json schemas - v1
const (
	ReportAssetsSchemaV1Name = "ReportAssetsV1"
	PatchAssetSchemaV1Name   = "PatchAssetV1"
	PutAssetSchemaV1Name     = "PutAssetV1"
)

// json schemas - v2
const (
	QueryIntelV2SchemaName                    = "QueryIntelligenceV2"
	TextQueryIntelV2SchemaName                = "TextQueryIntelligenceV2"
	QueriesIntelBulkSchemaName                = "BulkQueries"
	AsyncChildQueriesResultSchemaName         = "ReportAsyncChildQueriesResultsSchema.json"
	InvalidationRequestSchemaName             = "InvalidationRequest"
	AsyncInvalidationRequestSchemaName        = "AsyncInvalidationRequest"
	InvalidationRegistrationRequestSchemaName = "InvalidationRegistrationRequest"
	TenantEventRequestSchemaName              = "TenantEventRequest"
	ValidateTenantsRequestSchemaName          = "ValidateTenantRequest"
	ValidateQueriesRequestSchemaName          = "ValidateQueriesRequest"
	QueryV2SchemaName                         = "QueryV2"
	LocalSchema                               = "local"
)

// KnownSchemas is a map of all known schemas when validating assets
type KnownSchemas map[string][]byte
