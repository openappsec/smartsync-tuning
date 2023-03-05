package models

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/log"
)

const (
	// APIV1 is api version v1
	APIV1 = "v1"
	// APIV2 is api version v2
	APIV2 = "v2"
	// APILegacy is the legacy api version
	APILegacy = "legacy"
	// StartString is the string of the start cursor
	StartString = "start"
	// ZeroValueCursorConst is the base64 encoded string of the start cursor
	ZeroValueCursorConst = "MDow"

	defaultAPIVersion = APIV1

	defaultSortBy                = "name"
	defaultLimit                 = 20
	defaultBucketNumberForFacets = 20

	separatorKeyValue = ":"

	// ConfKeyIsAgentRun the configuration key for knowing if its agent intelligence
	ConfKeyIsAgentRun = "isAgentRun"
)

// QueryResultStatus represents the possible query response status for api version v2
type QueryResultStatus string

// known query result status
const (
	QueryResultStatusInProgress QueryResultStatus = "inProgress"
	QueryResultStatusDone       QueryResultStatus = "done"
)

// QueryResponseType determines which type of response the query algorithm will return - assets or assetCollections
type QueryResponseType string

// known query response types
const (
	QueryResponseTypeAssets           QueryResponseType = "assets"
	QueryResponseTypeAssetCollections QueryResponseType = "assetCollections"
)

// query classifications
const (
	SecurityQueryClassification = "security"
	PagingQueryClassification   = "paging"
)

// Identity contains the identifying information of the client
type Identity struct {
	TenantID string `json:"tenantId"`
	SourceID string `json:"sourceId"`
	Jwt      string `json:"jwt"`
}

// ReportedAssets is the way an asset is sent
type ReportedAssets struct {
	Assets Assets `json:"assets"`
}

// ReportedAsyncChildQueriesResult represents the query result returned by async child during async communication
type ReportedAsyncChildQueriesResult struct {
	QueriesReport AsyncChildQueriesResult `json:"queriesReport"`
}

// ReportedAssetQuery is the query sent by the client for an asset query operation
type ReportedAssetQuery struct {
	Limit      int        `json:"limit,omitempty" bson:"limit"`
	Offset     int        `json:"offset,omitempty" bson:"offset"`
	Query      Query      `json:"query" bson:"query"`
	Projection []string   `json:"projection,omitempty" bson:"projection"`
	ObjectType ObjectType `json:"objectType,omitempty" bson:"objectType"`
}

// EnrichReportedQuery enrich a reported query with more information
func (rq *ReportedAssetQuery) EnrichReportedQuery() {
	if rq.Limit == 0 {
		rq.Limit = DefaultPaginationLimit
	}

	if rq.ObjectType == MissingObjectType {
		rq.ObjectType = DefaultObjectType
	}
}

// LogQuery logs a query (for metrics purposes)
func LogQuery(ctx context.Context, lt *LogTrail, query interface{}) {
	lt.LogDebug(ctx, "f6e07add-8e45-4b67-aa60-2da6b0fe3c3f", log.Fields{LogFieldQuery: query}, "Got new query")
}

// SimpleAssetQuery is the query sent by the client for an asset simple query operation after being parsed into a struct
type SimpleAssetQuery struct {
	Limit      int               `json:"limit" bson:"limit"`
	Offset     int               `json:"offset,omitempty" bson:"offset"`
	Query      map[string]string `json:"query" bson:"query"`
	Projection []string          `json:"projection" bson:"projection"`
}

// ConvertToQuery accepts a simple query and converts it into a regular query
func (sq SimpleAssetQuery) ConvertToQuery() ReportedAssetQuery {
	res := ReportedAssetQuery{
		Limit:      sq.Limit,
		Offset:     sq.Offset,
		Projection: sq.Projection,
	}

	query := Query{
		Operator: QueryOperatorAnd,
		Operands: nil,
	}
	for k, v := range sq.Query {
		query.Operands = append(query.Operands, Query{
			Operator: QueryOperatorEquals,
			Key:      k,
			Value:    v,
		})
	}
	res.Query = query
	return res
}

// ReportedIntelQuery is the query sent by the client for an intelligence query operation
// offset is pointer in order to be able to check if we got value from the user (its not nil)
type ReportedIntelQuery struct {
	Limit               int                  `json:"limit,omitempty" bson:"limit"`
	Offset              *int                 `json:"offset,omitempty" bson:"offset"`
	SortBy              string               `json:"sortBy,omitempty" bson:"sortBy"`
	Query               Query                `json:"query" bson:"query"`
	RequestedAttributes []RequestedAttribute `json:"requestedAttributes,omitempty" bson:"requestedAttributes"`
	ObjectType          ObjectType           `json:"objectType,omitempty" bson:"objectType"`
	QueryTypes          *QueryTypes          `json:"queryTypes,omitempty" bson:"queryTypes"`
	Facets              *ReportedFacets      `json:"facets,omitempty" bson:"facets"`
}

// String implements the Stringer interface. It instructs how to print the ReportedIntelQuery struct while using %+v, %v or %s
func (q ReportedIntelQuery) String() string {
	if q.Offset != nil {
		return fmt.Sprintf("{Query: %+v, Limit: %d, Offset: %d, RequestedAttributes: %+v}", q.Query, q.Limit, *q.Offset, q.RequestedAttributes)
	}
	return fmt.Sprintf("{Query: %+v, Limit: %d, Offset: <nil>, RequestedAttributes: %+v}", q.Query, q.Limit, q.RequestedAttributes)
}

// ConvertToAssetQuery takes the acted upon ReportedIntelQuery and creates from it a ReportedAssetQuery.
func (q ReportedIntelQuery) ConvertToAssetQuery() ReportedAssetQuery {
	return convertToAssetQuery(q.Limit, q.Offset, q.Query, q.RequestedAttributes, q.ObjectType)
}

// AddObjectType adds the default object type to the query
func (q *ReportedIntelQuery) AddObjectType() {
	q.ObjectType = DefaultObjectType
}

// ConvertToQueryWithoutObjectType returns a copy of the ReportedIntelQuery without the ObjectType
func (q ReportedIntelQuery) ConvertToQueryWithoutObjectType() ReportedIntelQuery {
	return ReportedIntelQuery{
		Query:               q.Query,
		Limit:               q.Limit,
		Offset:              q.Offset,
		SortBy:              q.SortBy,
		RequestedAttributes: q.RequestedAttributes,
	}
}

// ConvertToIntelQueryV2 takes the acted upon ReportedIntelQuery and creates from it a IntelQueryV2.
func (q ReportedIntelQuery) ConvertToIntelQueryV2() IntelQueryV2 {
	return IntelQueryV2{
		Limit:               q.Limit,
		Query:               q.Query,
		RequestedAttributes: q.RequestedAttributes,
		Skip:                q.Offset,
		ResponseType:        QueryResponseTypeAssets,
		ObjectType:          q.ObjectType,
	}
}

// Validate returns true if the query is valid, or false otherwise.
func (q ReportedIntelQuery) Validate() error {
	keys := make(map[string]struct{})
	for _, reqAttr := range q.RequestedAttributes {
		if _, ok := keys[reqAttr.Key]; ok {
			return errors.Errorf("Requested attribute key %s already exists", reqAttr.Key).SetClass(errors.ClassBadInput)
		}

		keys[reqAttr.Key] = struct{}{}
	}

	return nil
}

// ConvertToAssetQuery get query related parameters and creates from it a ReportedAssetQuery.
// If no requested attributes exist then the query is maintained along with the limit otherwise
// the ReportedAssetQuery contains an AND query seeking the ReportedIntelQuery.Query along with an OR over all requestedAttributes with their chosen minConfidence
// the limit is maintained
func convertToAssetQuery(limit int, offset *int, query Query, requestedAttributes []RequestedAttribute, objType ObjectType) ReportedAssetQuery {
	if len(requestedAttributes) <= 0 {
		convQuery := ReportedAssetQuery{
			Limit: limit,
			Query: query,
		}
		if offset != nil {
			convQuery.Offset = *offset
		}

		if objType == MissingObjectType {
			convQuery.ObjectType = DefaultObjectType
		} else {
			convQuery.ObjectType = objType
		}

		return convQuery
	}

	attributeRequest := func(op string, key string, value interface{}) Query {
		return Query{
			Operator: op,
			Key:      key,
			Value:    value,
		}
	}

	var operandsAttributes []Query
	for _, v := range requestedAttributes {
		matchAttribute := attributeRequest(QueryOperatorExists, v.Key, true)
		operandsAttributes = append(operandsAttributes, matchAttribute)
		confidentAttribute := attributeRequest(QueryOperatorGTE, FieldConfidence, v.MinConfidence)
		operandsAttributes = append(operandsAttributes, confidentAttribute)
	}

	convQuery := ReportedAssetQuery{
		Limit: limit,
		Query: Query{
			Operator: QueryOperatorAnd,
			Operands: []Query{
				query,
				{
					Operator: QueryOperatorOr,
					Operands: operandsAttributes,
				},
			},
		},
	}

	if offset != nil {
		convQuery.Offset = *offset
	}

	if objType == MissingObjectType {
		convQuery.ObjectType = DefaultObjectType
	} else {
		convQuery.ObjectType = objType
	}

	return convQuery
}

// IntelQueryV2 is the query sent by the client for an intelligence query operation for api version v2
// cursor is pointer in order to be able to check if we got value from the user (its not nil)
// offset and extSrcPage are created by the intelligence from the cursor, they are pointers in order to check if they have values as well
// responseType is the type of the response assets or assetCollections created by the intelligence
type IntelQueryV2 struct {
	Limit                      int                  `json:"limit,omitempty" bson:"limit"`
	Cursor                     *string              `json:"cursor,omitempty" bson:"cursor"`
	SortBy                     string               `json:"sortBy,omitempty" bson:"sortBy"`
	FullResponse               bool                 `json:"fullResponse,omitempty" bson:"fullResponse"`
	ExternalSourcesErrorStatus bool                 `json:"externalSourcesErrorStatus,omitempty" bson:"externalSourcesErrorStatus"`
	Query                      Query                `json:"query" bson:"query"`
	RequestedAttributes        []RequestedAttribute `json:"requestedAttributes,omitempty" bson:"requestedAttributes"`
	Skip                       *int                 `json:"skip,omitempty" bson:"skip"`
	ExtSrcPage                 *int                 `json:"extSrcPage,omitempty" bson:"extSrcPage"`
	ResponseType               QueryResponseType    `json:"responseType,omitempty" bson:"responseType"`
	AgentAuxDone               bool                 `json:"agentAuxDone,omitempty" bson:"agentAuxDone"`
	QueryFromAgent             bool                 `json:"queryFromAgent,omitempty" bson:"queryFromAgent"`
	ObjectType                 ObjectType           `json:"objectType,omitempty" bson:"objectType"`
	QueryTypes                 *QueryTypes          `json:"queryTypes,omitempty" bson:"queryTypes"`
	SourcesFromQuery           SourcesFromQuery     `json:"sourcesFromQuery,omitempty" bson:"sourcesFromQuery"`
	Facets                     *ReportedFacets      `json:"facets,omitempty" bson:"facets"`
}

const (
	// ErrInvalidCursor is returned when the cursor is invalid
	ErrInvalidCursor = "invalid cursor"

	// ErrInvalidQuery is returned when the query is invalid
	ErrInvalidQuery = "invalid query"
)

// Parse parses the intel query and sets default values, returns an error if the query is invalid
func (q *IntelQueryV2) Parse() error {
	if len(q.SourcesFromQuery.SourcesToQuery) <= 0 {
		q.SourcesFromQuery.SourcesToQuery = make(map[string]struct{})
	}

	if len(q.SourcesFromQuery.SourcesNotToQuery) <= 0 {
		q.SourcesFromQuery.SourcesNotToQuery = make(map[string]struct{})
	}

	if q.Cursor != nil {
		if err := q.DecodeCursor(); err != nil {
			return errors.Wrap(err, "failed to decode cursor").SetClass(errors.ClassInternal).SetLabel(ErrInvalidCursor)
		}
	}

	q.AddResponseType()
	q.AddSortBy()
	q.AddLimit()
	q.AddObjectType()
	q.AddDefaultsForFacets()
	if err := q.Validate(); err != nil {
		return errors.Wrap(err, "failed to validate query").SetClass(errors.ClassBadInput).SetLabel(ErrInvalidQuery)
	}

	return nil
}

// ReportedFacets are facets as they are reported in a QueryV2 request body
type ReportedFacets struct {
	BucketNumber int          `json:"bucketNumber"`
	OnlyFacets   bool         `json:"onlyFacets"`
	Aggregations Aggregations `json:"aggregations"`
}

// Aggregation details the field on which user wishes to get Facets on
type Aggregation struct {
	Key string `json:"key"`
}

// Aggregations is a list of Aggregation
type Aggregations []Aggregation

// ReturnedFacets are the facets reported in the response body
type ReturnedFacets struct {
	Aggregations Facets `json:"aggregations,omitempty"`
}

// QueryTypes represents all the query types the intelligence support
type QueryTypes struct {
	MultiTenant *TenantsList `json:"multiTenant,omitempty" bson:"multiTenant"`
	TextQuery   bool         `json:"textQuery,omitempty" bson:"textQuery"`
}

// QueryTypeName string representation of the different supported queryTypes
type QueryTypeName string

// String representation of the supported query types
const (
	MultiTenantQueryType QueryTypeName = "multiTenantQueryType"
	TextQueryQueryType   QueryTypeName = "textQueryQueryType"
)

// ApplicableQueryTypes is a map of all queryTypes which appeared in a query and were set to "true"
type ApplicableQueryTypes map[QueryTypeName]struct{}

// SourcesFromQuery represents the sources that the user asked about in the query
type SourcesFromQuery struct {
	SourcesToQuery    map[string]struct{} `json:"sourcesToQuery,omitempty" bson:"sourcesToQuery"`
	SourcesNotToQuery map[string]struct{} `json:"sourcesNotToQuery,omitempty" bson:"sourcesNotToQuery"`
}

// GetCorrelationID returns the query id of the intelligence query for correlation.
// If the query has a cursor, it sets the cursor to start so paging queries can be correlated.
func (q IntelQueryV2) GetCorrelationID() string {
	var cursor string
	if q.Cursor != nil {
		cursor = *q.Cursor
		*q.Cursor = StartString
	}

	// Set the cursor back to what it was before
	defer func() {
		if q.Cursor != nil {
			*q.Cursor = cursor
		}
	}()

	bQuery, err := json.Marshal(q)
	if err != nil {
		log.Errorf("Error marshalling query %+v: %v", q, err)
		return ""
	}

	return CalculateSha256Sum(bQuery)
}

// ID calculates and returns the id of the query
func (q IntelQueryV2) ID(ctx context.Context) string {
	bQuery, err := json.Marshal(q)
	if err != nil {
		log.WithContextAndEventID(ctx, "9daf4683-9297-4857-9298-55fe9f3974c1").Errorf("Error marshalling query %+v: %v", q, err)
		return ""
	}

	return CalculateSha256Sum(bQuery)
}

// CalculateSha256Sum returns the sha256 checksum of data.
func CalculateSha256Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// String implements the Stringer interface. It instructs how to print the IntelQueryV2 struct while using %+v, %v or %s
func (q IntelQueryV2) String() string {
	if q.Cursor != nil && q.Skip != nil && q.ExtSrcPage != nil {
		return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor %s, Skip: %d, ExtSrcPage: %d, SortBy: %s, RequestedAttributes: %+v}", q.Query, q.Limit, *q.Cursor, *q.Skip, *q.ExtSrcPage, q.SortBy, q.RequestedAttributes)
	} else if q.Cursor != nil {
		if q.Skip != nil {
			return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor %s, Skip: %d, ExtSrcPage: <nil>, SortBy: %s, RequestedAttributes: %+v}", q.Query, q.Limit, *q.Cursor, *q.Skip, q.SortBy, q.RequestedAttributes)
		} else if q.ExtSrcPage != nil {
			return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor %s, Skip: <nil>, ExtSrcPage: %d, SortBy: %s, RequestedAttributes: %+v}", q.Query, q.Limit, *q.Cursor, *q.ExtSrcPage, q.SortBy, q.RequestedAttributes)
		}
		return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor %s, Skip: <nil>, ExtSrcPage: <nil>, SortBy: %s, RequestedAttributes: %+v}", q.Query, q.Limit, *q.Cursor, q.SortBy, q.RequestedAttributes)
	} else if q.Skip != nil {
		if q.ExtSrcPage != nil {
			return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor <nil>, Skip: %d, ExtSrcPage: %d, SortBy: %s, RequestedAttributes: %+v}", q.Query, q.Limit, *q.Skip, *q.ExtSrcPage, q.SortBy, q.RequestedAttributes)
		}
		return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor <nil>, Skip: %d, ExtSrcPage: <nil>, SortBy: %s, RequestedAttributes: %+v}", q.Query, q.Limit, *q.Skip, q.SortBy, q.RequestedAttributes)
	} else if q.ExtSrcPage != nil {
		return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor <nil>, Skip: <nil>, ExtSrcPage: %d, SortBy: %s, RequestedAttributes: %+v}", q.Query, q.Limit, *q.ExtSrcPage, q.SortBy, q.RequestedAttributes)
	}
	return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor <nil>, Skip: <nil>, ExtSrcPage: <nil>, SortBy: %s, RequestedAttributes: %+v}", q.Query, q.Limit, q.SortBy, q.RequestedAttributes)
}

// GetQueryClassification returns the query classification (either "security" or "paging")
func (q IntelQueryV2) GetQueryClassification() string {
	if q.Cursor != nil {
		return PagingQueryClassification
	}

	return SecurityQueryClassification
}

// DecodeCursor decodes the cursor and create skip and external source page
func (q *IntelQueryV2) DecodeCursor() error {
	if *q.Cursor == StartString {
		zeroValueCursor := ZeroValueCursorConst
		q.Cursor = &zeroValueCursor
	}

	skip, extSrcPage, err := ExtractSkipAndExtSrcPageFromCursor(*q.Cursor)
	if err != nil {
		return errors.Wrap(err, "Failed to convert query param 'cursor' to 'skip' and 'extSrcPage'")
	}

	q.Skip = skip
	q.ExtSrcPage = extSrcPage

	return nil
}

// EncodeCursor encode the skip and external source page and creates cursor
func EncodeCursor(skip, extSrcPage int) string {
	cursorStr := fmt.Sprintf("%s:%s", strconv.Itoa(skip), strconv.Itoa(extSrcPage))
	cursorEncoded := base64.StdEncoding.EncodeToString([]byte(cursorStr))
	return cursorEncoded
}

// ConvertToAssetQuery takes the acted upon intelQueryV2 and creates from it a ReportedAssetQuery.
func (q IntelQueryV2) ConvertToAssetQuery() ReportedAssetQuery {
	return convertToAssetQuery(q.Limit, q.Skip, q.Query, q.RequestedAttributes, q.ObjectType)
}

// ConvertToReportedIntelQuery takes the acted upon intelQueryV2 and creates from it a ReportedIntelQuery.
func (q IntelQueryV2) ConvertToReportedIntelQuery(isAux bool) ReportedIntelQuery {
	res := ReportedIntelQuery{
		Limit:               q.Limit,
		Query:               q.Query,
		RequestedAttributes: q.RequestedAttributes,
	}

	if isAux {
		res.Offset = q.ExtSrcPage
	} else {
		res.Offset = q.Skip
	}

	// For backward compatibility, add objectType to the request only if it's != "asset"
	// TODO - consider remove this part after telling everyone to change the API to always support objectType
	if q.ObjectType != DefaultObjectType {
		res.ObjectType = q.ObjectType
	}

	if q.QueryTypes != nil && len(q.QueryTypes.GetApplicableQueryTypes()) > 0 {
		res.QueryTypes = q.QueryTypes
	}

	if q.Facets != nil {
		res.Facets = q.Facets
	}

	return res
}

// AddSortBy adds the default sort by value (for paging query) to the query if its empty
func (q *IntelQueryV2) AddSortBy() {
	if q.SortBy == "" {
		q.SortBy = defaultSortBy
	}
}

// AddLimit adds the default limit to the query if its empty
func (q *IntelQueryV2) AddLimit() {
	if q.Limit == 0 {
		q.Limit = defaultLimit
	}
}

// AddResponseType adds the default response type value to the query if its empty (assetCollections)
func (q *IntelQueryV2) AddResponseType() {
	if q.ResponseType == "" {
		q.ResponseType = QueryResponseTypeAssetCollections
	}
}

// AddObjectType adds the default ObjectType to the query in case it's missing
func (q *IntelQueryV2) AddObjectType() {
	if q.ObjectType == MissingObjectType {
		q.ObjectType = DefaultObjectType
	}
}

// AddDefaultsForFacets adds the default values for requested facets (if they exist in query)
func (q *IntelQueryV2) AddDefaultsForFacets() {
	if q.Facets != nil {
		if q.Facets.BucketNumber == 0 {
			q.Facets.BucketNumber = defaultBucketNumberForFacets
		}
	}
}

// IsFacetsOnlyQuery returns true in case the query is for Facets only - otherwise returns false
func (q *IntelQueryV2) IsFacetsOnlyQuery() bool {
	if q.Facets == nil || !q.Facets.OnlyFacets {
		return false
	}

	return true
}

// Validate returns true if the query is valid, or false otherwise.
func (q *IntelQueryV2) Validate() error {
	keys := make(map[string]struct{})
	for _, reqAttr := range q.RequestedAttributes {
		if _, ok := keys[reqAttr.Key]; ok {
			return errors.Errorf("Requested attribute key %s already exists", reqAttr.Key).SetClass(errors.ClassBadInput)
		}

		keys[reqAttr.Key] = struct{}{}
	}

	return nil
}

// RequestedAttribute is the query requested data
type RequestedAttribute struct {
	Key           string `json:"key"`
	MinConfidence int    `json:"minConfidence"`
}

// UnmarshalJSON unmarshals a JSON string to a artifact.
// Using this override custom unmarshal help us to unmarshal some fields according to other ones.
// In this case, unmarshal the RequestedAttribute field to have default min confidence value if its not set.
func (r *RequestedAttribute) UnmarshalJSON(b []byte) error {
	type alias RequestedAttribute
	var reqAtt alias
	if err := json.Unmarshal(b, &reqAtt); err != nil {
		return err
	}
	if reqAtt.MinConfidence <= 0 {
		reqAtt.MinConfidence = DefaultMinConfidence
	}
	*r = RequestedAttribute(reqAtt)
	return nil
}

// SimpleIntelQuery is the query sent by the client for an intelligence simple query operation after being parsed into a struct
type SimpleIntelQuery struct {
	Limit               int               `json:"limit" bson:"limit"`
	Offset              *int              `json:"offset" bson:"offset"`
	Query               map[string]string `json:"query" bson:"query"`
	RequestedAttributes []string          `json:"requestedAttributes" bson:"requestedAttributes"`
	MinConfidence       int               `json:"minConfidence"`
}

// String implements the Stringer interface. It instructs how to print the SimpleIntelQuery struct while using %+v, %v or %s
func (sq SimpleIntelQuery) String() string {
	if sq.Offset != nil {
		return fmt.Sprintf("{Query: %+v, Limit: %d, Offset: %d, RequestedAttributes: %+v, MinConfidence: %d}", sq.Query, sq.Limit, *sq.Offset, sq.RequestedAttributes, sq.MinConfidence)
	}
	return fmt.Sprintf("{Query: %+v, Limit: %d, Offset: <nil>, RequestedAttributes: %+v, MinConfidence: %d}", sq.Query, sq.Limit, sq.RequestedAttributes, sq.MinConfidence)
}

// ConvertToQuery accepts a simple query and converts it into a regular query
func (sq SimpleIntelQuery) ConvertToQuery() ReportedIntelQuery {
	res := ReportedIntelQuery{
		Limit:  sq.Limit,
		Offset: sq.Offset,
	}

	res.Query = MapToQuery(sq.Query)
	res.RequestedAttributes = ListToRequesterAttributes(sq.RequestedAttributes, sq.MinConfidence)
	return res
}

// Validate returns true if the query is valid, or false otherwise.
func (sq SimpleIntelQuery) Validate() error {
	keys := make(map[string]struct{})
	for _, reqAttr := range sq.RequestedAttributes {
		if _, ok := keys[reqAttr]; ok {
			return errors.Errorf("Requested attribute key %s already exists", reqAttr).SetClass(errors.ClassBadInput)
		}

		keys[reqAttr] = struct{}{}
	}

	return nil
}

// MapToQuery accepts a simple query map and converts it into a query
func MapToQuery(simpleQuery map[string]string) Query {
	query := Query{
		Operator: QueryOperatorAnd,
	}

	for k, v := range simpleQuery {
		query.Operands = append(query.Operands, Query{
			Operator: QueryOperatorEquals,
			Key:      k,
			Value:    v,
		})
	}

	return query
}

// ListToRequesterAttributes accepts a list of string and converts it into a array of RequestedAttribute
func ListToRequesterAttributes(requestedAttributes []string, minConfidence int) []RequestedAttribute {
	var rAttributes []RequestedAttribute
	for _, ra := range requestedAttributes {
		rAttributes = append(rAttributes, RequestedAttribute{
			Key:           ra,
			MinConfidence: minConfidence,
		})
	}

	return rAttributes
}

// CopyGob deepcopys source value to destination reference to a value.
//
// Accepts optional buf, it's reset on return
func CopyGob[T any](source T, destination *T, buf io.ReadWriter) error {
	if buf == nil {
		buf = &bytes.Buffer{}
	}

	enc := gob.NewEncoder(buf)
	dec := gob.NewDecoder(buf)
	if err := enc.Encode(source); err != nil {
		return errors.Wrapf(err, "Failed encoding source %#v to gob", source)
	}

	if err := dec.Decode(destination); err != nil {
		return errors.Wrapf(err, "Failed decoding source %#v from gob to destination %#v", source, destination)
	}

	return nil
}

// RemoveByIndex removes the element at index from slice and returns the updated slice.
//
// Note: to prevent memory leaks, slice[index] is overwritten with its type zero value.
func RemoveByIndex[T any](slice []T, index int) []T {
	var zero T
	slice[index] = zero
	return append(slice[:index], slice[index+1:]...)
}

// SimpleIntelQueryV2 is the query sent by the client for an intelligence simple query operation after being parsed into a struct for api version v2
type SimpleIntelQueryV2 struct {
	Limit               int               `json:"limit,omitempty" bson:"limit"`
	Cursor              *string           `json:"cursor,omitempty" bson:"cursor"`
	Skip                *int              `json:"skip,omitempty" bson:"skip"`
	ExtSrcPage          *int              `json:"extSrcPage,omitempty" bson:"extSrcPage"`
	SortBy              string            `json:"sortBy,omitempty" bson:"sortBy"`
	Query               map[string]string `json:"query" bson:"query"`
	RequestedAttributes []string          `json:"requestedAttributes,omitempty" bson:"requestedAttributes"`
	MinConfidence       int               `json:"minConfidence,omitempty"`
	ObjectType          ObjectType        `json:"objectType,omitempty"`
}

// String implements the Stringer interface. It instructs how to print the SimpleIntelQuery struct while using %+v, %v or %s
func (sq SimpleIntelQueryV2) String() string {
	if sq.Cursor != nil && sq.Skip != nil && sq.ExtSrcPage != nil {
		return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor %s, Skip: %d, ExtSrcPage: %d, SortBy: %s, RequestedAttributes: %+v}", sq.Query, sq.Limit, *sq.Cursor, *sq.Skip, *sq.ExtSrcPage, sq.SortBy, sq.RequestedAttributes)
	} else if sq.Cursor != nil {
		if sq.Skip != nil {
			return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor %s, Skip: %d, ExtSrcPage: <nil>, SortBy: %s, RequestedAttributes: %+v}", sq.Query, sq.Limit, *sq.Cursor, *sq.Skip, sq.SortBy, sq.RequestedAttributes)
		} else if sq.ExtSrcPage != nil {
			return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor %s, Skip: <nil>, ExtSrcPage: %d, SortBy: %s, RequestedAttributes: %+v}", sq.Query, sq.Limit, *sq.Cursor, *sq.ExtSrcPage, sq.SortBy, sq.RequestedAttributes)
		}
		return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor %s, Skip: <nil>, ExtSrcPage: <nil>, SortBy: %s, RequestedAttributes: %+v}", sq.Query, sq.Limit, *sq.Cursor, sq.SortBy, sq.RequestedAttributes)
	} else if sq.Skip != nil {
		if sq.ExtSrcPage != nil {
			return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor <nil>, Skip: %d, ExtSrcPage: %d, SortBy: %s, RequestedAttributes: %+v}", sq.Query, sq.Limit, *sq.Skip, *sq.ExtSrcPage, sq.SortBy, sq.RequestedAttributes)
		}
		return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor <nil>, Skip: %d, ExtSrcPage: <nil>, SortBy: %s, RequestedAttributes: %+v}", sq.Query, sq.Limit, *sq.Skip, sq.SortBy, sq.RequestedAttributes)
	} else if sq.ExtSrcPage != nil {
		return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor <nil>, Skip: <nil>, ExtSrcPage: %d, SortBy: %s, RequestedAttributes: %+v}", sq.Query, sq.Limit, *sq.ExtSrcPage, sq.SortBy, sq.RequestedAttributes)
	}
	return fmt.Sprintf("{Query: %+v, Limit: %d, Cursor <nil>, Skip: <nil>, ExtSrcPage: <nil>, SortBy: %s, RequestedAttributes: %+v}", sq.Query, sq.Limit, sq.SortBy, sq.RequestedAttributes)
}

// ConvertToQuery accepts a simple query and converts it into a regular query for api version v2
func (sq SimpleIntelQueryV2) ConvertToQuery() IntelQueryV2 {
	res := IntelQueryV2{
		Limit:      sq.Limit,
		Cursor:     sq.Cursor,
		Skip:       sq.Skip,
		ExtSrcPage: sq.ExtSrcPage,
		SortBy:     sq.SortBy,
		ObjectType: sq.ObjectType,
	}

	res.Query = MapToQuery(sq.Query)
	res.RequestedAttributes = ListToRequesterAttributes(sq.RequestedAttributes, sq.MinConfidence)
	return res
}

// Validate returns true if the query is valid, or false otherwise.
func (sq SimpleIntelQueryV2) Validate() error {
	keys := make(map[string]struct{})
	for _, reqAttr := range sq.RequestedAttributes {
		if _, ok := keys[reqAttr]; ok {
			return errors.Errorf("Requested attribute key %s already exists", reqAttr).SetClass(errors.ClassBadInput)
		}

		keys[reqAttr] = struct{}{}
	}

	return nil
}

// QueryResponse is the response of a query
type QueryResponse struct {
	Assets Assets `json:"assets" bson:"assets"`
}

// QueryResponseAssetCollections is the response of a query in v2 for AssetCollections
type QueryResponseAssetCollections struct {
	AssetCollections           AssetCollections            `json:"assetCollections"`
	Status                     QueryResultStatus           `json:"status"`
	TotalNumAssets             int                         `json:"totalNumAssets"`
	Cursor                     string                      `json:"cursor"`
	Facets                     *ReturnedFacets             `json:"facets,omitempty"`
	ExternalSourcesErrorStatus *ExternalSourcesErrorStatus `json:"externalSourcesErrorStatus,omitempty"`
}

// ExternalSourcesErrorStatus represents the external sources http response error status
type ExternalSourcesErrorStatus []ExternalSourceErrorStatus

// ExternalSourceErrorStatus represents the external source http response error status
type ExternalSourceErrorStatus struct {
	SourceID     string     `json:"sourceID"`
	SourceName   SourceName `json:"sourceName"`
	StatusCode   int        `json:"statusCode"`
	ErrorMessage string     `json:"errorMessage"`
}

// QueryResponseAssets is the response of a query in v2 for Assets
type QueryResponseAssets struct {
	Assets                     Assets                      `json:"assets"`
	Status                     QueryResultStatus           `json:"status"`
	TotalNumAssets             int                         `json:"totalNumAssets"`
	Cursor                     string                      `json:"cursor"`
	Facets                     *ReturnedFacets             `json:"facets,omitempty"`
	ExternalSourcesErrorStatus *ExternalSourcesErrorStatus `json:"externalSourcesErrorStatus,omitempty"`
}

// ExternalSourceResponseAssets is the response of a query in v2 for Assets
type ExternalSourceResponseAssets struct {
	Assets           Assets            `json:"assets"`
	Status           QueryResultStatus `json:"status"`
	TotalNumAssets   int               `json:"totalNumAssets"`
	Cursor           string            `json:"cursor"`
	Facets           *ReturnedFacets   `json:"facets,omitempty"`
	EmptyResCacheTTL *time.Duration    `json:"emptyResCacheTTL,omitempty"`
}

// ReportResponse is the response for a report of assets
type ReportResponse struct {
	IDs []string `json:"ids" bson:"ids"`
}

// AssetUpdate contain the fields that needs to be update inside the asset
type AssetUpdate map[string]interface{}

// EnrichAssetUpdate enrich an asset update with more information
func (au *AssetUpdate) EnrichAssetUpdate() {
	if ttl, ok := (*au)[FieldTTL]; ok {
		(*au)[FieldExpirationTime] = time.Now().Add(time.Duration(int(ttl.(float64))) * time.Second)
	}
}

// Validate validate an update asset request
func (au AssetUpdate) Validate() error {
	var attributesObjectUpdate bool
	var attributeFieldUpdate bool
	var tagsObjectUpdate bool
	var tagFieldUpdate bool

	attributesPrefix := FieldAttributes + "."
	tagsPrefix := FieldTags + "."

	for k := range au {
		if k == FieldAttributes {
			attributesObjectUpdate = true
		} else if k == FieldTags {
			tagsObjectUpdate = true
		} else if strings.HasPrefix(k, attributesPrefix) {
			attributeFieldUpdate = true
		} else if strings.HasPrefix(k, tagsPrefix) {
			tagFieldUpdate = true
		}
	}

	if attributesObjectUpdate && attributeFieldUpdate {
		return errors.Errorf("Update asset request can't contain both (%s) and (%s) keys", FieldAttributes, attributesPrefix).SetClass(errors.ClassBadInput)
	}

	if tagsObjectUpdate && tagFieldUpdate {
		return errors.Errorf("Update asset request can't contain both (%s) and (%s) keys", FieldTags, tagsPrefix).SetClass(errors.ClassBadInput)
	}

	return nil
}

// GetAPIVersionFromContext gets the api version from the context
func GetAPIVersionFromContext(ctx context.Context) (string, error) {
	apiV := ctxutils.ExtractString(ctx, ctxutils.ContextKeyAPIVersion)
	if apiV == "" {
		apiV = defaultAPIVersion
	}
	switch apiV {
	case APIV1, APIV2, APILegacy:
		return apiV, nil
	}
	return "", errors.Errorf("API version passed through context (%s) is unsupported. Versions supported are [%v]", apiV, []string{APIV1, APIV2})
}

// ExtractSkipAndExtSrcPageFromCursor creates skip and external source page from the cursor
func ExtractSkipAndExtSrcPageFromCursor(paramValue string) (*int, *int, error) {
	cursor, err := url.QueryUnescape(paramValue)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Failed to unescape value (%s)", paramValue).SetClass(errors.ClassBadInput)
	}

	data, err := base64.StdEncoding.DecodeString(cursor)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to decode cursor in base64")
	}

	stringData := string(data)
	splitData := strings.Split(stringData, separatorKeyValue)
	if len(splitData) != 2 {
		return nil, nil, errors.New("Failed to parse cursor, the cursor isn't valid").SetClass(errors.ClassBadInput)
	}

	skip, err := strconv.Atoi(splitData[0])
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to convert 'skip' to int - cursor isn't valid").SetClass(errors.ClassBadInput)
	}
	if skip < 0 {
		return nil, nil, errors.Errorf("Query parameter 'skip' should be a number greater than or equal to 0, got: %s - cursor isn't valid", skip).SetClass(errors.ClassBadInput)
	}

	extSrcPage, err := strconv.Atoi(splitData[1])
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to convert 'extSrcPage' to int - cursor isn't valid").SetClass(errors.ClassBadInput)
	}
	if extSrcPage < 0 {
		return nil, nil, errors.Errorf("Query parameter 'extSrcPage' should be a number greater than or equal to 0, got: %s - cursor isn't valid", extSrcPage).SetClass(errors.ClassBadInput)
	}

	return &skip, &extSrcPage, nil
}

// CheckForAssetIDs check if the query is a simple query of operator: EQUALS, key: assetID, value: <ListOfAssetIDs>
// if so, return the assetID, else return an empty string
func (q IntelQueryV2) CheckForAssetIDs(ctx context.Context) ([]string, error) {
	query := q.Query
	if query.Operator == "" {
		return []string{}, nil
	}

	o := query.Operator
	switch o {
	case QueryOperatorEquals, QueryOperatorEqualsLow:
		if query.Key == FieldAssetID {
			if assetID, ok := query.Value.(string); ok {
				return []string{assetID}, nil
			}

			return []string{}, errors.Errorf("Received intelligence query with unsupported assetID type, expected string")
		}
	case QueryOperatorIn, QueryOperatorInLow:
		if query.Key == FieldAssetID {
			valAsArray, ok := query.Value.([]interface{})
			if !ok {
				return []string{}, errors.Errorf("Received intelligence query with unsupported assetID type, expected []interface{}")
			}

			assetIDs := make([]string, 0, len(valAsArray))
			for _, assetID := range valAsArray {
				if assetID, ok := assetID.(string); ok {
					assetIDs = append(assetIDs, assetID)
					continue
				}

				return []string{}, errors.Errorf("Received intelligence query with unsupported assetID type, expected []string")
			}

			return assetIDs, nil
		}
	default:
		return []string{}, nil
	}

	return []string{}, nil
}

// ReportedBulkQuery is the bulk query API structure of the intelligence
type ReportedBulkQuery struct {
	TenantID *string      `json:"tenantId,omitempty"`
	Index    *int         `json:"index,omitempty"`
	Query    IntelQueryV2 `json:"query"`
}

// ReportedBulkQueries is the bulk queries API structure of the intelligence
type ReportedBulkQueries struct {
	Queries []ReportedBulkQuery `json:"queries"`
}

// CreateErrorResponse creates a BulkError from index and err
func CreateErrorResponse(index int, err error) BulkError {
	if errors.IsClassTopLevel(err, errors.ClassBadInput) {
		return BulkError{
			Index:      index,
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("Bad request. Error: %s", err.Error()),
		}
	}

	if errors.IsClassTopLevel(err, errors.ClassUnauthorized) {
		return BulkError{
			Index:      index,
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("Unauthorized. Error: %s", err.Error()),
		}
	}

	return BulkError{
		Index:      index,
		StatusCode: http.StatusInternalServerError,
		Message:    fmt.Sprintf("Internal server error. Error: %s", err.Error()),
	}
}

// Parse parses the ReportedBulkQueries using IntelQueryV2.Parse and validates the queries' tenants with the given identity, returns a map of the query index to its result
func (rbq *ReportedBulkQueries) Parse(ctx context.Context, lt *LogTrail, identity Identity, validTenants TenantsMap) map[int]BulkQueryResAndError {
	// the map key is the index of the query in the request
	res := make(map[int]BulkQueryResAndError, len(rbq.Queries))
	for queryIndex := range rbq.Queries {
		index := queryIndex
		// TODO: fix case that user set the index to 0 on a query that isn't the first in the array
		if rbq.Queries[index].Index == nil {
			rbq.Queries[index].Index = &index
		}

		newIdentity := identity
		if rbq.Queries[index].TenantID != nil {
			if identity.Jwt != "" && len(validTenants) > 0 {
				if _, ok := validTenants[*rbq.Queries[index].TenantID]; !ok {
					bulkErr := CreateErrorResponse(index, errors.Errorf("Unauthorized tenant Id").SetClass(errors.ClassUnauthorized))
					res[*rbq.Queries[index].Index] = BulkQueryResAndError{Error: &bulkErr}
					continue
				}
			}

			newIdentity = Identity{TenantID: *rbq.Queries[index].TenantID, SourceID: identity.SourceID}
		}

		res[*rbq.Queries[index].Index] = BulkQueryResAndError{Identity: newIdentity}

		query := &rbq.Queries[index].Query
		if err := query.Parse(); err != nil {
			if errors.IsLabel(err, ErrInvalidCursor) {
				bulkErr := CreateErrorResponse(index, errors.Errorf("Invalid cursor").SetClass(errors.ClassBadInput))
				res[*rbq.Queries[index].Index] = BulkQueryResAndError{Identity: newIdentity, Error: &bulkErr}
				continue
			}

			if errors.IsLabel(err, ErrInvalidQuery) {
				bulkErr := CreateErrorResponse(index, errors.Errorf("Invalid query").SetClass(errors.ClassBadInput))
				res[*rbq.Queries[index].Index] = BulkQueryResAndError{Identity: newIdentity, Error: &bulkErr}
				continue
			}
		}

		if query.ResponseType != QueryResponseTypeAssetCollections {
			bulkErr := CreateErrorResponse(index, errors.Errorf("Query response type sent"+
				" is not supported, only asset collection is supported").SetClass(errors.ClassBadInput))
			res[index] = BulkQueryResAndError{Identity: newIdentity, Error: &bulkErr}
			continue
		}
	}

	return res
}

// LogBulkQueries logs all queries in the bulk separately (for metrics purposes)
func (rbq *ReportedBulkQueries) LogBulkQueries(ctx context.Context, lt *LogTrail) {
	for _, q := range rbq.Queries {
		LogQuery(ctx, lt, q.Query)
	}
}

// Validate returns true if the query is valid, or false otherwise.
func (rbq ReportedBulkQueries) Validate() error {
	for _, query := range rbq.Queries {
		if err := query.Query.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// BulkError is the bulk query error response
type BulkError struct {
	Index      int    `json:"index"`
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}

// BulkErrors is a list of the bulk query error response
type BulkErrors []BulkError

// BulkQueryRes is the bulk query `query response` response
type BulkQueryRes struct {
	Index    int                           `json:"index"`
	Response QueryResponseAssetCollections `json:"response"`
}

// BulkQueryResList is the bulk query `query response` response array
type BulkQueryResList []BulkQueryRes

// BulkQueriesRes is the bulk queries response
type BulkQueriesRes struct {
	Errors           BulkErrors       `json:"errors,omitempty"`
	QueriesResponses BulkQueryResList `json:"queriesResponse,omitempty"`
}

// BulkQueryResAndError is the bulk query's response, error and parsed identity
type BulkQueryResAndError struct {
	BulkResponse *BulkQueryRes
	Error        *BulkError
	Identity     Identity
}

// ToBulkQueryResAndErrorMap maps the BulkQueriesRes to a map of the query index and its BulkQueryResAndError
func (bqr *BulkQueriesRes) ToBulkQueryResAndErrorMap() map[int]BulkQueryResAndError {
	res := make(map[int]BulkQueryResAndError)
	for _, qr := range bqr.QueriesResponses {
		res[qr.Index] = BulkQueryResAndError{BulkResponse: &qr}
	}

	for _, err := range bqr.Errors {
		res[err.Index] = BulkQueryResAndError{Error: &err}
	}

	return res
}

// GetApplicableQueryTypes returns a map with all the queryTypes
func (qt QueryTypes) GetApplicableQueryTypes() ApplicableQueryTypes {
	res := ApplicableQueryTypes{}
	if qt.MultiTenant != nil {
		res[MultiTenantQueryType] = struct{}{}
	}

	if qt.TextQuery {
		res[TextQueryQueryType] = struct{}{}
	}

	return res
}
