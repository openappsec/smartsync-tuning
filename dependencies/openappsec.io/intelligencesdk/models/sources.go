package models

import (
	"context"

	"openappsec.io/errors"
	"openappsec.io/log"
)

const (
	// IntelAccessTypeFog represent the intelligence source type fog needs jwt
	IntelAccessTypeFog = "fog"
	// IntelAccessTypeDirect represent the intelligence source type direct does not need jwt (needs tenant id and source id)
	IntelAccessTypeDirect = "direct"

	// ErrorLabelPartialResponseFromSources error label represents that didn't get a full response from external sources during query flow
	ErrorLabelPartialResponseFromSources = "notAllSourcesFound"
)

// CommunicationType for external source of type async or sync
type CommunicationType string

// known communication types
const (
	CommTypeAsync CommunicationType = "async"
	CommTypeSync  CommunicationType = "sync"
)

// PublicTenants is the list of tenants that any other tenant can see their assets
type PublicTenants []string

// Auxiliary exposes an interface of auxiliary related actions
// mockgen -destination mocks/mock_Auxiliary.go -package mocks -mock_names Auxiliary=MockAuxiliary openappsec.io/intelligencesdk/models Auxiliary
type Auxiliary interface {
	GetData(ctx context.Context, lt *LogTrail, host string, reqBody ReportedIntelQuery, tenantID string) (ExternalSourceResponseAssets, *HTTPResError, error)
	ReportValidationErrors(ctx context.Context, lt *LogTrail, validationErrors AssetValidationErrors, host string)
}

// Intelligence exposes an interface of intelligence related actions
// mockgen -destination mocks/mock_intelligence.go -package mocks -mock_names Intelligence=MockIntelligence openappsec.io/intelligencesdk/models Intelligence
type Intelligence interface {
	PostAssets(ctx context.Context, lt *LogTrail, identity Identity, updateExistingAssets bool, ass Assets) (ReportResponse, error)
	SimpleQueryIntelAssets(ctx context.Context, lt *LogTrail, identity Identity, query map[string]string, limit *int, offset *int, requestedAttributes []string, minConfidence *int) (QueryResponse, error)
	SimpleQueryIntelAssetCollections(ctx context.Context, lt *LogTrail, identity Identity, query map[string]string, limit *int, cursor *string, requestedAttributes []string, minConfidence *int) (QueryResponseAssetCollections, error)
	QueryIntelAssets(ctx context.Context, lt *LogTrail, identity Identity, query ReportedIntelQuery) (QueryResponse, error)
	QueryIntelAssetCollections(ctx context.Context, lt *LogTrail, identity Identity, query IntelQueryV2) (QueryResponseAssetCollections, error)
	QueryIntelAssetsV2(ctx context.Context, lt *LogTrail, identity Identity, query IntelQueryV2) (QueryResponseAssets, error)
	GetAsset(ctx context.Context, lt *LogTrail, identity Identity, assetID string) (Asset, error)
	PutAsset(ctx context.Context, lt *LogTrail, identity Identity, assetID string, asset Asset) error
	PatchAsset(ctx context.Context, lt *LogTrail, identity Identity, assetID string, updateAsset AssetUpdate) error
	DeleteAsset(ctx context.Context, lt *LogTrail, identity Identity, assetID string) error
	RegisterExternalSource(ctx context.Context, lt *LogTrail, identity Identity, extSrcReg ExternalSourceReg) (string, error)
	AsyncGetQueriesAndInvalidation(ctx context.Context, lt *LogTrail, identity Identity) (AsyncChildQueryAndInvalidationRequests, error)
	AsyncPostQueries(ctx context.Context, lt *LogTrail, identity Identity, queries ReportedAsyncChildQueriesResult) (AsyncParentQueriesStatus, error)
	AsyncBulkQueries(ctx context.Context, lt *LogTrail, identity Identity, queries ReportedBulkQueries) (BulkQueriesRes, error)
	AsyncInvalidation(ctx context.Context, lt *LogTrail, identity Identity, invalidations AsyncInvalidations) (Assets, error)
	Invalidation(ctx context.Context, lt *LogTrail, identity Identity, invalidations ReportedInvalidations) error
	AsyncValidateTenants(ctx context.Context, lt *LogTrail, identity Identity, reportedMultiTenants ReportedMultiTenants) (TenantsMap, error)
	HealthCheck(ctx context.Context) error
}

// KnownAllTenantsSources is the map of all the known external sources that their permission type is `allTenants`
// map from the external source sourceID to the external source name.
type KnownAllTenantsSources map[string]string

// CrossTenantDataMap is the struct that hold the cross tenant invalidation matcher and its key
type CrossTenantDataMap struct {
	Key                 string           `json:"key"`
	InvalidationMatcher InvalidationData `json:"invalidationMatcher"`
}

// CrossTenantDataMaps is a slice of CrossTenantDataMap
type CrossTenantDataMaps []CrossTenantDataMap

// CrossTenantQueries is a struct containing the cross tenant key and the queries that a source want to be notified
// when they are invalidated.
type CrossTenantQueries struct {
	// Key is the private key of cross tenant API
	Key string `json:"key"`
	// Queries is the queries the source wants to be notified on, each query is parsed in the handler
	// so this slice holds the parsed queries.
	Queries []IntelQueryV2 `json:"queries"`
	// OriginalQueries holds the queries the source wants to be notified on as it was originally sent by the source, before parsing.
	OriginalQueries []IntelQueryV2 `json:"originalQueries"`
}

// CrossTenantDataMapKeys is the map of keys to specific data maps, used for cross tenant invalidation registration
type CrossTenantDataMapKeys map[string]InvalidationData

// Match returns true if CrossTenantDataMapKeys contains the key its value matches the given invalidation matcher.
func (m CrossTenantDataMapKeys) Match(key string, invalidationMatcher InvalidationData) bool {
	if _, ok := m[key]; !ok {
		return false
	}

	if !invalidationMatcher.Match(m[key]) {
		return false
	}

	return true
}

// Matcher is the map of the external source accepted values
type Matcher map[string]string

// ExternalSourceRegistrationDataMap saves the data map that the external source passes to the intelligence in the registration
type ExternalSourceRegistrationDataMap struct {
	SupportGeneralAttributes bool               `json:"supportGeneralAttributes"`
	SupportPaging            bool               `json:"supportPaging"`
	Matcher                  Matcher            `json:"matcher"`
	RequestedAttributes      []DataRequestField `json:"requestedAttributes,omitempty"`
	ObjectType               ObjectType         `json:"objectType,omitempty"`
	SupportedTenantIds       []string           `json:"supportedTenantIds,omitempty"`
}

// ExternalSourceRegistrationDataMaps represents list of ExternalSourceRegistrationDataMap
type ExternalSourceRegistrationDataMaps []ExternalSourceRegistrationDataMap

// ExternalSourceDataMap saves the data map that the external source passes to the intelligence in the registration for internal use
type ExternalSourceDataMap struct {
	SupportGeneralAttributes bool                `json:"supportGeneralAttributes"`
	SupportPaging            bool                `json:"supportPaging"`
	Matcher                  Matcher             `json:"matcher"`
	RequestedAttributes      []DataRequestField  `json:"requestedAttributes,omitempty"`
	ObjectType               ObjectType          `json:"objectType,omitempty"`
	SupportedTenantIds       map[string]struct{} `json:"supportedTenantIds,omitempty"`
}

// ExternalSourceDataMaps represents list of ExternalSourceDataMap
type ExternalSourceDataMaps []ExternalSourceDataMap

// ExternalSourceCachedDataMap is the map used to save the external source registration in Cache (per object type)
type ExternalSourceCachedDataMap map[ObjectType]ExternalSourceDataMaps

// SourceName represents the name of an external sources the intelligence communicate with
type SourceName string

// ExternalSourceReg represents the registration body sent from user
type ExternalSourceReg struct {
	Name                 SourceName                         `json:"name"`
	QueryURL             string                             `json:"queryUrl"`
	APIVersion           string                             `json:"apiVersion"`
	CommunicationType    CommunicationType                  `json:"communicationType"`
	RegisterToAllQueries *RegisterToAllQueriesReg           `json:"registerToAllQueries,omitempty"`
	DataMaps             ExternalSourceRegistrationDataMaps `json:"dataMap,omitempty"`
	SourcesIds           []string                           `json:"sourcesIds,omitempty"`
	Capabilities         Capabilities                       `json:"capabilities,omitempty"`
}

// Capabilities contains the external source special capabilities
type Capabilities struct {
	MultiTenantQuery bool `json:"multiTenantQuery,omitempty"`
	TextQuery        bool `json:"textQuery,omitempty"`
}

// RegisterToAllQueriesReg is added when the source wants to register to answer all queries
// If the source wants it can also contain the specific tenants it can answer queries for
// If the source doesn't know te tenants the array is empty
type RegisterToAllQueriesReg struct {
	SupportedTenantID []string `json:"supportedTenantIds,omitempty"`
}

// RegisterToAllQueries is added when the source wants to register to answer all queries
// If the source wants it can also contain the specific tenants it can answer queries for
// If the source doesn't know te tenants the array is empty
type RegisterToAllQueries struct {
	SupportedTenantID map[string]struct{} `json:"supportedTenantIds,omitempty"`
}

// RegisterToAllQueriesListToMap converts the register to all queries value from ist to map
func (r RegisterToAllQueriesReg) RegisterToAllQueriesListToMap() RegisterToAllQueries {
	mapTenantIDs := make(map[string]struct{})
	for _, tenantID := range r.SupportedTenantID {
		mapTenantIDs[tenantID] = struct{}{}
	}

	return RegisterToAllQueries{
		SupportedTenantID: mapTenantIDs,
	}
}

// ExternalSource represents the external source for the intelligence
type ExternalSource struct {
	Name                 SourceName                  `json:"name"`
	SourceID             string                      `json:"sourceID"`
	TenantID             string                      `json:"tenantID"`
	Host                 string                      `json:"host"`
	APIVersion           string                      `json:"apiVersion"`
	CommunicationType    CommunicationType           `json:"communicationType"`
	RegisterToAllQueries *RegisterToAllQueries       `json:"registerToAllQueries"`
	DataMap              ExternalSourceCachedDataMap `json:"dataMaps,omitempty"`
	SourcesIds           map[string]struct{}         `json:"sourcesIds,omitempty"`
	Capabilities         Capabilities                `json:"capabilities,omitempty"`
}

// ExtSourcesAndPublicTenants is a struct containing the external sources and public tenants which is used as parameters
// for some functions
type ExtSourcesAndPublicTenants struct {
	PublicTenants   PublicTenants
	ExternalSources ExternalSources
}

// ExternalSourceDataMapFromListToMap converts the list of datamaps to a map with the different object types are keys
func (a *ExternalSourceReg) ExternalSourceDataMapFromListToMap(ctx context.Context, lt *LogTrail) (ExternalSourceCachedDataMap, error) {
	res := make(ExternalSourceCachedDataMap)
	for _, dataMap := range a.DataMaps {
		keyName := DefaultObjectType
		switch dataMap.ObjectType {
		case ObjectTypeAsset:
			keyName = ObjectTypeAsset
		case ObjectTypeZone:
			keyName = ObjectTypeZone
		case ObjectTypePolicyPackage:
			keyName = ObjectTypePolicyPackage
		case ObjectTypeConfiguration:
			keyName = ObjectTypeConfiguration
		case ObjectTypeSession:
			keyName = ObjectTypeSession
		case "":
			keyName = DefaultObjectType
		default:
			lt.LogErrorf(ctx, "69a39241-2d31-4f83-ad9b-f839b7094e21", log.Fields{}, "Oh no this shouldn't have happened - objectType %s is not supported. Should have been caught during the JSON schema validation of the datamap.", dataMap.ObjectType)
			return ExternalSourceCachedDataMap{}, errors.Errorf("objectType %s is not supported. Should have been caught during the JSON schema validation of the datamap.", dataMap.ObjectType)
		}

		dataMapAfterChange := ExternalSourceDataMap{
			SupportGeneralAttributes: dataMap.SupportGeneralAttributes,
			SupportPaging:            dataMap.SupportPaging,
			Matcher:                  dataMap.Matcher,
			RequestedAttributes:      dataMap.RequestedAttributes,
			ObjectType:               keyName,
		}

		if len(dataMap.SupportedTenantIds) > 0 {
			mapTenantIDs := make(map[string]struct{})
			for _, tenantID := range dataMap.SupportedTenantIds {
				mapTenantIDs[tenantID] = struct{}{}
			}

			dataMapAfterChange.SupportedTenantIds = mapTenantIDs
		}

		if dataMaps, ok := res[keyName]; !ok {
			res[keyName] = ExternalSourceDataMaps{dataMapAfterChange}
		} else {
			res[keyName] = append(dataMaps, dataMapAfterChange)
		}
	}

	return res, nil
}

// ExternalSourceSourceIDListToMap converts the list of source ids to a map
func (a *ExternalSourceReg) ExternalSourceSourceIDListToMap() map[string]struct{} {
	res := make(map[string]struct{})
	for _, id := range a.SourcesIds {
		res[id] = struct{}{}
	}

	return res
}

// ExternalSourceDataMapFromMapToList converts the sources' data map from map to list
func (ex *ExternalSourceDataMaps) ExternalSourceDataMapFromMapToList() ExternalSourceRegistrationDataMaps {
	var extSrcRegDataMaps ExternalSourceRegistrationDataMaps
	for _, dataMap := range *ex {
		reqDataMap := ExternalSourceRegistrationDataMap{
			SupportGeneralAttributes: dataMap.SupportGeneralAttributes,
			SupportPaging:            dataMap.SupportPaging,
			Matcher:                  dataMap.Matcher,
			RequestedAttributes:      dataMap.RequestedAttributes,
			ObjectType:               dataMap.ObjectType,
		}

		if len(dataMap.SupportedTenantIds) > 0 {
			var listTenantIDs []string
			for tenantID := range dataMap.SupportedTenantIds {
				listTenantIDs = append(listTenantIDs, tenantID)
			}

			reqDataMap.SupportedTenantIds = listTenantIDs
		}

		extSrcRegDataMaps = append(extSrcRegDataMaps, reqDataMap)
	}

	return extSrcRegDataMaps
}

// ExternalSources represents the external sources for the intelligence
// key - external source id (source id)
type ExternalSources map[string]ExternalSource

// AsyncExternalSources represents the async external sources for the intelligence
type AsyncExternalSources []ExternalSource

// IntelSource represents the intelligence source
type IntelSource struct {
	Name       SourceName   `json:"name"`
	AccessType string       `json:"accessType"`
	APIVersion string       `json:"apiVersion"`
	Intel      Intelligence `json:"intel"`
}

// IntelSources represents the intelligence sources
type IntelSources []IntelSource

// AuthRequirementsMatch checks if the intelligence source has the data in need in the identity struct
func (i IntelSource) AuthRequirementsMatch(identity Identity) bool {
	if i.AccessType == IntelAccessTypeFog && identity.Jwt != "" {
		return true
	} else if i.AccessType == IntelAccessTypeDirect && identity.TenantID != "" && identity.SourceID != "" {
		return true
	}
	return false
}

// SyncExternalRequest represents the external sources request (auxiliary source and intelligence)
type SyncExternalRequest interface {
	ExecuteRequest(ctx context.Context, lt *LogTrail, tenantID string, isAgent bool) (ExternalSourceResponseAssets, *HTTPResError, error)
	GetTenantIDAndSourceID() (string, string)
	GetName() SourceName
	ReportValidationErrors(ctx context.Context, lt *LogTrail, validationErrors AssetValidationErrors)
	IsIntelSource() bool
	ChangeAssetsTenantAndSource() bool
	SupportMultiTenantQuery() bool
	AddMultiTenantsToQuery(tenants TenantsList) AuxReq
}

// SyncExternalRequests represents many external sources
type SyncExternalRequests []SyncExternalRequest

// Sources represents the intelligence sources sync and async
type Sources struct {
	Sync  SyncExternalRequests
	Async AsyncExternalSources
}

// AuxReq represents the auxiliary source request
type AuxReq struct {
	AuxSource  ExternalSource     `json:"auxSource"`
	AuxAdapter Auxiliary          `json:"auxAdapter"`
	Request    ReportedIntelQuery `json:"request"`
}

// ExecuteRequest executes the request to the auxiliary source
func (a AuxReq) ExecuteRequest(ctx context.Context, lt *LogTrail, tenantID string, isAgent bool) (ExternalSourceResponseAssets, *HTTPResError, error) {
	auxRes, httpResErr, err := a.AuxAdapter.GetData(ctx, lt, a.AuxSource.Host, a.Request, tenantID)
	if err != nil {
		return ExternalSourceResponseAssets{}, httpResErr, errors.Wrapf(err, "Could not get desired data from auxiliary source (%s)", a.AuxSource.Name)
	}

	return auxRes, nil, nil
}

// GetTenantIDAndSourceID return the tenant id and source id of the auxiliary source
func (a AuxReq) GetTenantIDAndSourceID() (string, string) {
	return a.AuxSource.TenantID, a.AuxSource.SourceID
}

// GetName return the name of the auxiliary source
func (a AuxReq) GetName() SourceName {
	return a.AuxSource.Name
}

// ReportValidationErrors sends an HTTP request to the Aux Source with the asset validation errors found
func (a AuxReq) ReportValidationErrors(ctx context.Context, lt *LogTrail, validationErrors AssetValidationErrors) {
	a.AuxAdapter.ReportValidationErrors(ctx, lt, validationErrors, a.AuxSource.Host)
}

// IsIntelSource return false since AuxReq is not an intelligence source
func (a AuxReq) IsIntelSource() bool {
	return false
}

// ChangeAssetsTenantAndSource return true if the auxiliary has more than one source
// since in this case the auxiliary should decide the tenant and source id of the asset
func (a AuxReq) ChangeAssetsTenantAndSource() bool {
	if len(a.AuxSource.SourcesIds) <= 0 {
		return true
	}

	return false
}

// SupportMultiTenantQuery return true if the auxiliary supports multi tenant
func (a AuxReq) SupportMultiTenantQuery() bool {
	return a.AuxSource.Capabilities.MultiTenantQuery
}

// AddMultiTenantsToQuery adds a list of tenants to support the multi tenant query
func (a AuxReq) AddMultiTenantsToQuery(tenants TenantsList) AuxReq {
	if a.Request.QueryTypes != nil {
		a.Request.QueryTypes.MultiTenant = &tenants
	} else {
		a.Request.QueryTypes = &QueryTypes{
			MultiTenant: &tenants,
		}
	}

	return a
}

// IntelReq represents the intelligence source request
type IntelReq struct {
	IntelSource IntelSource `json:"intelSource"`
	Request     struct {
		IntelQuery IntelQueryV2 `json:"intelQuery"`
		Identity   Identity     `json:"identity"`
	} `json:"request"`
}

// ExecuteRequest executes the request to the intelligence source
func (i IntelReq) ExecuteRequest(ctx context.Context, lt *LogTrail, tenantID string, isAgent bool) (ExternalSourceResponseAssets, *HTTPResError, error) {
	logFields := log.Fields{LogFieldSourceName: i.IntelSource.Name, LogFieldAccessType: i.IntelSource.AccessType,
		LogFieldQuery: i.Request.IntelQuery}
	lt.LogDebug(ctx, "7b312f15-554a-4424-a34b-c3f687ea8610", logFields, "Performing external intelligence source call")

	apiV, err := GetAPIVersionFromContext(ctx)
	if err != nil {
		return ExternalSourceResponseAssets{}, nil, errors.Wrapf(err, "Could not get desired data from intelligence source (%s)", i.IntelSource.Name)
	}

	var res ExternalSourceResponseAssets
	switch apiV {
	case APIV1:
		intelRes, err := i.IntelSource.Intel.QueryIntelAssets(ctx, lt, i.Request.Identity, i.Request.IntelQuery.ConvertToReportedIntelQuery(false))
		if err != nil {
			return ExternalSourceResponseAssets{}, nil, errors.Wrapf(err, "Could not get desired data from intelligence source (%s)", i.IntelSource.Name)
		}

		res = ExternalSourceResponseAssets{Assets: intelRes.Assets}
	case APIV2:
		if isAgent {
			i.Request.IntelQuery.QueryFromAgent = true
		}

		resQuery, err := i.IntelSource.Intel.QueryIntelAssetsV2(ctx, lt, i.Request.Identity, i.Request.IntelQuery)
		if err != nil {
			return ExternalSourceResponseAssets{}, nil, errors.Wrapf(err, "Could not get desired data from intelligence source (%s)", i.IntelSource.Name)
		}

		res = ExternalSourceResponseAssets{
			Assets:         resQuery.Assets,
			Status:         resQuery.Status,
			TotalNumAssets: resQuery.TotalNumAssets,
			Cursor:         resQuery.Cursor,
			Facets:         resQuery.Facets,
		}
	default:
		lt.LogWarnf(ctx, "f4542c0b-7efb-49b6-a2fa-989e7e48ad58", log.Fields{}, "Could not get desired data from intelligence source api version not supported (%s)", apiV)
	}

	return res, nil, nil
}

// GetTenantIDAndSourceID return the tenant id and source id of caller
func (i IntelReq) GetTenantIDAndSourceID() (string, string) {
	return i.Request.Identity.TenantID, i.Request.Identity.SourceID
}

// GetName return the name of the intelligence source
func (i IntelReq) GetName() SourceName {
	return i.IntelSource.Name
}

// ReportValidationErrors sends an HTTP request to the Intelligence Source with the asset validation errors found
func (i IntelReq) ReportValidationErrors(ctx context.Context, lt *LogTrail, validationErrors AssetValidationErrors) {
	// TODO - Change once we implement Error API for Intelligence Source - INXT-24012
	log.WithContext(ctx).Infof("Found Validation errors for Intelligence Source: %+v", validationErrors)
}

// IsIntelSource return true since IntelReq is intelligence source
func (i IntelReq) IsIntelSource() bool {
	return true
}

// ChangeAssetsTenantAndSource return false since for intelligence source
// the tenant and source id shouldn't be changes
func (i IntelReq) ChangeAssetsTenantAndSource() bool {
	return false
}

// SupportMultiTenantQuery return true since the intelligence always support multi tenant query
func (i IntelReq) SupportMultiTenantQuery() bool {
	return true
}

// AddMultiTenantsToQuery adds a list of tenants to support the multi tenant query
// NOT IN USE
func (i IntelReq) AddMultiTenantsToQuery(tenants TenantsList) AuxReq {
	return AuxReq{}
}

// DoQueryTypesMatchCapabilities checks if the reported capabilities of the external source match the reported queryTypes of the provided query
func (es ExternalSource) DoQueryTypesMatchCapabilities(queryTypes ApplicableQueryTypes) bool {
	for qt := range queryTypes {
		if qt == MultiTenantQueryType {
			// Not having "multiTenant" as a queryType impacts WHAT is sent to the external source, not IF it should be sent.
			// Therefore, it isn't crossed with the capabilities and doesn't impact the verdict of whether there's a match or not.
			continue
		}

		if qt == TextQueryQueryType && !es.Capabilities.TextQuery {
			return false
		}
	}

	return true
}
