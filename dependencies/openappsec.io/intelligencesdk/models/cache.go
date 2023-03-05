package models

import (
	"fmt"
	"reflect"
	"time"

	"openappsec.io/errors"
)

// QueryStatus represents the stage of a record in the query status cache
type QueryStatus string

// known query status
const (
	QueryStatusCreated QueryStatus = "created"
	QueryStatusWorking QueryStatus = "working"
	QueryStatusDone    QueryStatus = "done"
)

// QueryStatusRecord represents a record in the query status cache
type QueryStatusRecord struct {
	ReqTenantID       string         `json:"reqTenantID"`
	ReqSourceID       string         `json:"reqSourceID"`
	SrcTenantID       string         `json:"srcTenantID"`
	SourceID          string         `json:"sourceId"`
	SourceName        SourceName     `json:"sourceName"`
	QueryID           string         `json:"queryId"`
	Query             IntelQueryV2   `json:"query"`
	Status            QueryStatus    `json:"status"`
	ReportedAssets    Assets         `json:"reportedAssets"`
	TotalNumAssets    int            `json:"totalNumAssets"`
	NumReportedAssets int            `json:"numReportedAssets"`
	CreationTime      time.Time      `json:"creationTime"`
	DoneWithError     bool           `json:"doneWithError"`
	Error             *HTTPResError  `json:"error"`
	Facets            ReturnedFacets `json:"facets"`
}

// QueryStatusRecords represents records in the query status cache
type QueryStatusRecords []QueryStatusRecord

// QueryStatusSumRecord represents query status summary records. Those records track the status of Sources needed to invoke a worker to get a query to done
type QueryStatusSumRecord struct {
	WaitingSources     map[string]bool `json:"waitingSources"`
	DoneWaitingSources int             `json:"doneWaitingSources"`
	Threshold          int             `json:"threshold"`
	WasWorkerSent      bool            `json:"wasWorkerSent"`
	CreatedAt          time.Time       `json:"createdAt"`
	Identity           Identity        `json:"identity"`
	CallIntelSource    bool            `json:"callIntelSource"`
}

// AsyncChildInvalidationRecord represents a record for the async child invalidation in the invalidation cache
type AsyncChildInvalidationRecord struct {
	Identity Identity `json:"identity"`
	AsyncChildInvalAndAssets
}

// AsyncChildInvalidationRecords represents records for the async child invalidation in the invalidation cache
type AsyncChildInvalidationRecords []AsyncChildInvalidationRecord

// GetAssetTypeFieldsFromQuery returns the asset type fields that are found in the query.
func GetAssetTypeFieldsFromQuery(query interface{}) (AssetTypeFields, error) {
	internalQuery := Query{}
	queryType := fmt.Sprintf("%s", reflect.TypeOf(query))
	switch queryType {
	case TypeReportedAssetQuery:
		assetQuery := query.(ReportedAssetQuery)
		internalQuery = assetQuery.Query
	case TypeReportedIntelQuery:
		intelQuery := query.(ReportedIntelQuery)
		internalQuery = intelQuery.Query
	case TypeIntelQueryV2:
		intelQueryV2 := query.(IntelQueryV2)
		internalQuery = intelQueryV2.Query
	default:
		return AssetTypeFields{}, errors.Errorf("This shouldn't happen! Unsupported query type, expected type of %s, %s or %s, got %s",
			TypeReportedAssetQuery, TypeReportedIntelQuery, TypeIntelQueryV2, queryType)
	}

	if reflect.ValueOf(internalQuery).IsZero() {
		return AssetTypeFields{}, nil
	}

	return internalQuery.ExtractAssetTypeFields()
}

// GetAssetTypeFieldsFromResult returns the missing asset type fields that are found in the result.
func GetAssetTypeFieldsFromResult(result interface{}, missingFields []string) AssetTypeFieldsList {
	assetTypeFieldsList := AssetTypeFieldsList{}
	queryResType := fmt.Sprintf("%s", reflect.TypeOf(result))
	switch queryResType {
	case TypeQueryResponseAssets:
		queryRes := result.(QueryResponseAssets)
		assetTypeFieldsList = queryRes.Assets.ExtractAssetsTypeFields(missingFields)
	case TypeQueryResponseAssetCollections:
		queryRes := result.(QueryResponseAssetCollections)
		assetTypeFieldsList = queryRes.AssetCollections.ExtractAssetsTypeFields(missingFields)
	}

	return assetTypeFieldsList
}

// InvalidationRegSrcData represent only the root fields from the InvalidationReg struct to be saved in the cache.
type InvalidationRegSrcData struct {
	Name              string            `json:"name"`
	TenantID          string            `json:"tenantId"`
	SourceID          string            `json:"sourceId"`
	URL               string            `json:"url"`
	APIVersion        string            `json:"apiVersion"`
	CommunicationType CommunicationType `json:"communicationType"`
	InvalidationData  InvalidationData  `json:"invalidationData"`
}

// InvalidationRegSrcDataList is a list of InvalidationRegSrcData
type InvalidationRegSrcDataList []InvalidationRegSrcData

// CreateInvalidationRegSrcData create InvalidationRegSrcData from InvalidationRegistration and specific InvalidationData
func (ir InvalidationReg) CreateInvalidationRegSrcData(identity Identity, invalData InvalidationData) InvalidationRegSrcData {
	return InvalidationRegSrcData{
		Name:              ir.Name,
		TenantID:          identity.TenantID,
		SourceID:          identity.SourceID,
		URL:               ir.URL,
		APIVersion:        ir.APIVersion,
		CommunicationType: ir.CommunicationType,
		InvalidationData:  invalData,
	}
}
