package models

// AsyncChildQueryRequest represents the query request of the child during async communication
type AsyncChildQueryRequest struct {
	QueryID     string       `json:"queryId"`
	Query       IntelQueryV2 `json:"query"`
	ReqTenantID string       `json:"reqTenantID"`
	ReqSourceID string       `json:"reqSourceID"`
}

// AsyncChildQueriesRequest represents the queries request of the child during async communication
type AsyncChildQueriesRequest []AsyncChildQueryRequest

// AsyncChildQueryAndInvalidationRequests represents the query request and cache invalidation records of the child during async communication
type AsyncChildQueryAndInvalidationRequests struct {
	AsyncChildQueriesRequest    AsyncChildQueriesRequest      `json:"asyncChildQueriesRequest"`
	CacheInvalidationsAndAssets AsyncChildInvalidationRecords `json:"cacheInvalidationsAndAssets"`
	CacheInvalidationsRegData   InvalidationsData             `json:"cacheInvalidationsRegData"`
	FlushCacheTime              string                        `json:"flushCacheTime,omitempty"`
}

// AsyncChildQueryResult represents the query result of the child during async communication
type AsyncChildQueryResult struct {
	QueryID            string `json:"queryId"`
	QueryCorrelationID string `json:"queryCorrelationId"`
	// TODO need to add objectType of the query so that Async parent could check reported assets by child - INXT-24489
	Assets         Assets         `json:"assets"`
	Facets         ReturnedFacets `json:"facets"`
	TotalNumAssets int            `json:"totalNumAssets"`
	ReqTenantID    string         `json:"reqTenantID"`
	ReqSourceID    string         `json:"reqSourceID"`
}

// AsyncChildQueriesResult represents the query result of the child during async communication
type AsyncChildQueriesResult []AsyncChildQueryResult

// AsyncChildQueriesResultMap is map from queryID to AsyncChildQueryResult
type AsyncChildQueriesResultMap map[string]AsyncChildQueryResult

// AsyncParentQueryStatus represents the query status of the parent during async communication (after child return)
type AsyncParentQueryStatus struct {
	QueryID string `json:"queryId"`
	Status  int    `json:"status"`
}

// AsyncParentQueriesStatus represents the queries status of the parent during async communication (after child return)
type AsyncParentQueriesStatus []AsyncParentQueryStatus

// AsyncChildInvalAndAssets represents the invalidations occurs at the parent and the matching assets that was deleted
type AsyncChildInvalAndAssets struct {
	Invalidations InvalidationsData `json:"invalidations"`
	Assets        Assets            `json:"assets"`
}
