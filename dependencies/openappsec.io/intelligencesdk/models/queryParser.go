package models

import (
	"fmt"
	"strings"

	"openappsec.io/errors"
)

var (
	// MongoQueryOperatorMap maps intelligence operators to mongoDB operators
	MongoQueryOperatorMap = map[string]string{
		QueryOperatorExists:        "$exists",
		QueryOperatorExistsLow:     "$exists",
		QueryOperatorGTE:           "$gte",
		QueryOperatorGTELow:        "$gte",
		QueryOperatorLTELow:        "$lte",
		QueryOperatorGT:            "$gt",
		QueryOperatorGTLow:         "$gt",
		QueryOperatorLT:            "$lt",
		QueryOperatorLTLow:         "$lt",
		QueryOperatorNotIn:         "$nin",
		QueryOperatorNotInLow:      "$nin",
		QueryOperatorIn:            "$in",
		QueryOperatorInLow:         "$in",
		QueryOperatorNotEquals:     "$ne",
		QueryOperatorNotEqualsLow:  "$ne",
		QueryOperatorEquals:        "$eq",
		QueryOperatorEqualsLow:     "$eq",
		QueryOperatorAnd:           "$and",
		QueryOperatorAndLow:        "$and",
		QueryOperatorOr:            "$or",
		QueryOperatorOrLow:         "$or",
		QueryOperatorMatch:         "$regex",
		QueryOperatorMatchLow:      "$regex",
		QueryOperatorStartsWith:    "$regex",
		QueryOperatorStartsWithLow: "$regex",
		QueryOperatorContains:      "$regex",
		QueryOperatorContainsLow:   "$regex",
	}

	// CompoundOperators are the text query operators which in case exists in root, must be wrapped with a "compound" component
	CompoundOperators = []string{TextQueryOperatorMust, TextQueryOperatorMustNot, TextQueryOperatorShould, TextQueryOperatorFilter}
)

const (
	elemMatch = "$elemMatch"
	nGramLen  = 25

	// asset-db fields for nGram
	assetDBObject                  = "object."
	assetDBAttributesIPv6Addresses = assetDBObject + AttributesIPv6Addresses
	assetDBMainAttributesKeyIPv6   = assetDBObject + mainAttributesKeyIPv6
	assetDBTenantID                = assetDBObject + FieldTenantID
	assetDBSourceID                = assetDBObject + FieldSourceID
	assetDBAssetID                 = assetDBObject + FieldAssetID
	assetDBObjectID                = "objectId"
	assetDBIntelligenceID          = "intelligenceId"
	assetDBExternalID              = "externalId"
	assetDBELockedBySession        = "lockedBySession"
)

var (
	keysNotToShortValue = map[string]struct{}{
		AttributesIPv6Addresses:        {},
		mainAttributesKeyIPv6:          {},
		FieldTenantID:                  {},
		FieldSourceID:                  {},
		FieldAssetID:                   {},
		assetDBAttributesIPv6Addresses: {},
		assetDBMainAttributesKeyIPv6:   {},
		assetDBTenantID:                {},
		assetDBSourceID:                {},
		assetDBAssetID:                 {},
		assetDBObjectID:                {},
		assetDBIntelligenceID:          {},
		assetDBExternalID:              {},
		assetDBELockedBySession:        {},
	}
)

// MongoQuery is the format used to query Mongo
type MongoQuery map[string]interface{}

// FoundQueryKeys is a map of all the query keys found while parsing a query. Can be used to set a hint on MongoQuery
type FoundQueryKeys map[string]struct{}

// ParseIntelQueryToMongoQuery converts a Query to a query in Mongo query syntax
func ParseIntelQueryToMongoQuery(q Query) (MongoQuery, FoundQueryKeys, error) {
	parsedQuery, foundKeys, err := recParseIntelQueryToMongoQuery(q)
	if err != nil {
		return MongoQuery{}, FoundQueryKeys{}, err
	}

	return parsedQuery, foundKeys, nil
}

func recParseIntelQueryToMongoQuery(q Query) (MongoQuery, FoundQueryKeys, error) {
	if q.Operator == "" {
		return MongoQuery{}, FoundQueryKeys{}, nil
	}

	var parsedQuery MongoQuery
	var foundKeys FoundQueryKeys
	var err error

	o := q.Operator
	switch o {
	case QueryOperatorAnd, QueryOperatorAndLow,
		QueryOperatorOr, QueryOperatorOrLow,
		QueryOperatorElemMatchLow:
		parsedQuery, foundKeys, err = parseQueryAndOrCase(o, q)
	case QueryOperatorNotIn, QueryOperatorNotInLow,
		QueryOperatorIn, QueryOperatorInLow,
		QueryOperatorNotEquals, QueryOperatorNotEqualsLow,
		QueryOperatorEquals, QueryOperatorEqualsLow:
		parsedQuery = map[string]interface{}{
			q.Key: map[string]interface{}{
				MongoQueryOperatorMap[o]: q.Value,
			},
		}

	case QueryOperatorStartsWith, QueryOperatorStartsWithLow:
		parsedQuery = map[string]interface{}{
			q.Key: map[string]interface{}{
				MongoQueryOperatorMap[o]: "^" + q.Value.(string),
			},
		}

	case QueryOperatorContains, QueryOperatorContainsLow,
		QueryOperatorMatch, QueryOperatorMatchLow:
		parsedQuery = map[string]interface{}{
			q.Key: map[string]interface{}{
				MongoQueryOperatorMap[o]: q.Value.(string),
			},
		}

	case QueryOperatorExists, QueryOperatorExistsLow:
		parsedQuery = map[string]interface{}{
			q.Key: map[string]interface{}{
				MongoQueryOperatorMap[QueryOperatorExists]: q.Value.(bool),
			},
		}

	case QueryOperatorGT, QueryOperatorGTLow,
		QueryOperatorLT, QueryOperatorLTLow:
		var val float64
		switch v := q.Value.(type) {
		case int:
			val = float64(v)
		case float64:
			val = v
		default:
			parsedQuery = nil
			err = errors.Errorf("%s operator value (%+v) is not valid", o, v).SetClass(errors.ClassBadInput)
		}

		if err != nil {
			break
		}

		parsedQuery = map[string]interface{}{
			q.Key: map[string]interface{}{
				MongoQueryOperatorMap[o]: val,
			},
		}

	case QueryOperatorRange, QueryOperatorRangeLow:
		parsedQuery, err = convertRangeQuery(q)
	case QueryOperatorGTE, QueryOperatorGTELow, QueryOperatorLTE, QueryOperatorLTELow:
		parsedQuery = map[string]interface{}{
			q.Key: map[string]interface{}{
				MongoQueryOperatorMap[o]: q.Value,
			},
		}
	default:
		parsedQuery = nil
		foundKeys = nil
		err = errors.Errorf("Invalid query. Unknown operator: %s", o).SetClass(errors.ClassBadInput)
	}

	if q.Key != "" {
		foundKeys = FoundQueryKeys{q.Key: struct{}{}}
	}

	return parsedQuery, foundKeys, err
}

func parseQueryAndOrCase(operator string, q Query) (MongoQuery, FoundQueryKeys, error) {
	arr := make([]interface{}, len(q.Operands))
	allFoundKeys := FoundQueryKeys{}
	for i := 0; i < len(q.Operands); i++ {
		query, foundKeys, err := recParseIntelQueryToMongoQuery(q.Operands[i])
		if err != nil {
			return nil, nil, err
		}

		for key := range foundKeys {
			allFoundKeys[key] = struct{}{}
		}

		arr[i] = query
	}

	return MongoQuery{
		MongoQueryOperatorMap[operator]: arr,
	}, allFoundKeys, nil
}

func convertRangeQuery(q Query) (MongoQuery, error) {
	if strings.Contains(q.Key, AttributesPortsRange) {
		return convertPortsRangeQuery(q)
	}

	if strings.Contains(q.Key, AttributesIPv4AddressesRange) {
		return convertIPv4RangeQuery(q)
	}

	if strings.Contains(q.Key, AttributesIPv6AddressesRange) {
		return convertIPv6RangeQuery(q)
	}

	return nil, errors.Errorf("'range' operator should be used only for ipv4Addresses, ipv6Addresses and ports range field, got %s", q.Key).SetClass(errors.ClassBadInput)
}

func convertPortsRangeQuery(q Query) (MongoQuery, error) {
	finalQuery := func(minPort, maxPort int) (MongoQuery, error) {
		assetRangeStartBeforeQuery := MongoQuery{
			AttributesPortsRange: map[string]map[string]map[string]int{
				elemMatch: {
					Min: {MongoQueryOperatorMap[QueryOperatorLTELow]: minPort},
					Max: {MongoQueryOperatorMap[QueryOperatorGTELow]: minPort},
				},
			},
		}

		assetRangeEndAfterQuery := MongoQuery{
			AttributesPortsRange: map[string]map[string]map[string]int{
				elemMatch: {
					Min: {MongoQueryOperatorMap[QueryOperatorLTELow]: maxPort},
					Max: {MongoQueryOperatorMap[QueryOperatorGTELow]: maxPort},
				},
			},
		}

		assetRangeInMiddleQuery := MongoQuery{
			AttributesPortsRange: map[string]map[string]map[string]int{
				elemMatch: {
					Min: {MongoQueryOperatorMap[QueryOperatorGTELow]: minPort},
					Max: {MongoQueryOperatorMap[QueryOperatorLTELow]: maxPort},
				},
			},
		}

		return MongoQuery{
			MongoQueryOperatorMap[QueryOperatorOrLow]: []MongoQuery{assetRangeStartBeforeQuery, assetRangeEndAfterQuery, assetRangeInMiddleQuery},
		}, nil
	}

	// parse port to float64
	portFloatRange, ok := q.Value.([]float64)
	if !ok {
		// can be an interface if we got it from user
		portFloatRangeInterface, ok := q.Value.([]interface{})
		if !ok {
			return nil, errors.Errorf("Port range should be of type []float64 or []interface").SetClass(errors.ClassBadInput)
		}

		if len(portFloatRangeInterface) != 2 {
			return nil, errors.Errorf("Port range should be an array of 2 items").SetClass(errors.ClassBadInput)
		}

		minPort, ok := portFloatRangeInterface[0].(float64)
		if !ok {
			return nil, errors.Errorf("Port range value should be of type float64").SetClass(errors.ClassBadInput)
		}

		maxPort, ok := portFloatRangeInterface[1].(float64)
		if !ok {
			return nil, errors.Errorf("Port range value should be of type float64").SetClass(errors.ClassBadInput)
		}

		return finalQuery(int(minPort), int(maxPort))
	}

	if len(portFloatRange) != 2 {
		return nil, errors.Errorf("Port range should be an array of 2 items").SetClass(errors.ClassBadInput)
	}

	return finalQuery(int(portFloatRange[0]), int(portFloatRange[1]))
}

func convertIPv4RangeQuery(q Query) (MongoQuery, error) {
	finalQuery := func(minIpv4, maxIpv4 string) (MongoQuery, error) {
		ipv4MinInt, err := StringToIntIPv4(minIpv4)
		if err != nil {
			return nil, err
		}

		ipv4MaxInt, err := StringToIntIPv4(maxIpv4)
		if err != nil {
			return nil, err
		}

		assetRangeStartBeforeQuery := MongoQuery{
			AttributesIPv4AddressesRange: map[string]map[string]map[string]int{
				elemMatch: {
					Min: {MongoQueryOperatorMap[QueryOperatorLTELow]: ipv4MinInt},
					Max: {MongoQueryOperatorMap[QueryOperatorGTELow]: ipv4MinInt},
				},
			},
		}

		assetRangeEndAfterQuery := MongoQuery{
			AttributesIPv4AddressesRange: map[string]map[string]map[string]int{
				elemMatch: {
					Min: {MongoQueryOperatorMap[QueryOperatorLTELow]: ipv4MaxInt},
					Max: {MongoQueryOperatorMap[QueryOperatorGTELow]: ipv4MaxInt},
				},
			},
		}

		assetRangeInMiddleQuery := MongoQuery{
			AttributesIPv4AddressesRange: map[string]map[string]map[string]int{
				elemMatch: {
					Min: {MongoQueryOperatorMap[QueryOperatorGTELow]: ipv4MinInt},
					Max: {MongoQueryOperatorMap[QueryOperatorLTELow]: ipv4MaxInt},
				},
			},
		}

		return MongoQuery{
			MongoQueryOperatorMap[QueryOperatorOrLow]: []MongoQuery{assetRangeStartBeforeQuery, assetRangeEndAfterQuery, assetRangeInMiddleQuery},
		}, nil
	}

	// parse IP to int
	ipv4StringRange, ok := q.Value.([]string)
	if !ok {
		// can be an interface if we got it from user
		ipv4StringRangeInterface, ok := q.Value.([]interface{})
		if !ok {
			return nil, errors.Errorf("Ipv4 address range should be of type []string or []interface").SetClass(errors.ClassBadInput)
		}

		if len(ipv4StringRangeInterface) != 2 {
			return nil, errors.Errorf("Ipv4 address range should be an array of 2 items").SetClass(errors.ClassBadInput)
		}

		minIpv4, ok := ipv4StringRangeInterface[0].(string)
		if !ok {
			return nil, errors.Errorf("Ipv4 address range value should be of type string").SetClass(errors.ClassBadInput)
		}

		maxIpv4, ok := ipv4StringRangeInterface[1].(string)
		if !ok {
			return nil, errors.Errorf("Ipv4 address range value should be of type string").SetClass(errors.ClassBadInput)
		}

		return finalQuery(minIpv4, maxIpv4)
	}

	if len(ipv4StringRange) != 2 {
		return nil, errors.Errorf("Ipv4 address range should be an array of 2 items").SetClass(errors.ClassBadInput)
	}

	return finalQuery(ipv4StringRange[0], ipv4StringRange[1])
}

func convertIPv6RangeQuery(q Query) (MongoQuery, error) {
	finalQuery := func(minIpv6, maxIpv6 string) (map[string]interface{}, error) {
		ipv6MinInt, err := StringToIntIPv6(minIpv6)
		if err != nil {
			return nil, err
		}

		ipv6MaxInt, err := StringToIntIPv6(maxIpv6)
		if err != nil {
			return nil, err
		}

		assetRangeStartBeforeQuery := MongoQuery{
			AttributesIPv6AddressesRange: map[string]map[string]map[string]string{
				elemMatch: {
					Min: {MongoQueryOperatorMap[QueryOperatorLTELow]: ipv6MinInt.String()},
					Max: {MongoQueryOperatorMap[QueryOperatorGTELow]: ipv6MinInt.String()},
				},
			},
		}

		assetRangeEndAfterQuery := MongoQuery{
			AttributesIPv6AddressesRange: map[string]map[string]map[string]string{
				elemMatch: {
					Min: {MongoQueryOperatorMap[QueryOperatorLTELow]: ipv6MaxInt.String()},
					Max: {MongoQueryOperatorMap[QueryOperatorGTELow]: ipv6MaxInt.String()},
				},
			},
		}

		assetRangeInMiddleQuery := MongoQuery{
			AttributesIPv6AddressesRange: map[string]map[string]map[string]string{
				elemMatch: {
					Min: {MongoQueryOperatorMap[QueryOperatorGTELow]: ipv6MinInt.String()},
					Max: {MongoQueryOperatorMap[QueryOperatorLTELow]: ipv6MaxInt.String()},
				},
			},
		}

		return MongoQuery{
			MongoQueryOperatorMap[QueryOperatorOrLow]: []map[string]interface{}{assetRangeStartBeforeQuery, assetRangeEndAfterQuery, assetRangeInMiddleQuery},
		}, nil
	}

	// parse IP to int
	ipv6StringRange, ok := q.Value.([]string)
	if !ok {
		// can be an interface if we got it from user
		ipv6StringRangeInterface, ok := q.Value.([]interface{})
		if !ok {
			return nil, errors.Errorf("Ipv6 address range should be of type []string or []interface").SetClass(errors.ClassBadInput)
		}

		if len(ipv6StringRangeInterface) != 2 {
			return nil, errors.Errorf("Ipv6 address range should be an array of 2 items").SetClass(errors.ClassBadInput)
		}

		minIpv6, ok := ipv6StringRangeInterface[0].(string)
		if !ok {
			return nil, errors.Errorf("Ipv6 address range value should be of type string").SetClass(errors.ClassBadInput)
		}

		maxIpv6, ok := ipv6StringRangeInterface[1].(string)
		if !ok {
			return nil, errors.Errorf("Ipv6 address range value should be of type string").SetClass(errors.ClassBadInput)
		}

		return finalQuery(minIpv6, maxIpv6)
	}

	if len(ipv6StringRange) != 2 {
		return nil, errors.Errorf("Ipv6 address range should be an array of 2 items").SetClass(errors.ClassBadInput)
	}

	return finalQuery(ipv6StringRange[0], ipv6StringRange[1])
}

// ParseTextQueryToMongoQuery parses a query to fit Mongo's syntax for query used within the $search stage of an aggregation pipeline
func ParseTextQueryToMongoQuery(q Query) (MongoQuery, MongoQuery, error) {
	parsedSearchQuery, parsedMatchQuery, err := recParseTextQueryToMongoQuery(q)
	if err != nil {
		return MongoQuery{}, MongoQuery{}, err
	}

	for _, op := range CompoundOperators {
		if _, ok := parsedSearchQuery[op]; ok {
			return textQueryCompoundWrapper(parsedSearchQuery), parsedMatchQuery, nil
		}
	}

	return parsedSearchQuery, parsedMatchQuery, nil
}

func recParseTextQueryToMongoQuery(q Query) (MongoQuery, MongoQuery, error) {
	if q.Operator == "" {
		return MongoQuery{}, MongoQuery{}, nil
	}

	var parsedSearchQuery MongoQuery
	var parsedMatchQuery MongoQuery
	var err error

	o := q.Operator
	switch o {
	case QueryOperatorNotEquals, QueryOperatorNotEqualsLow,
		QueryOperatorEquals, QueryOperatorEqualsLow:
		switch o {
		case QueryOperatorNotEquals, QueryOperatorNotEqualsLow:
			parsedSearchQuery = turnTextQueryComponentToNot(getTextQueryBaseComponent(q))
		case QueryOperatorEquals, QueryOperatorEqualsLow:
			parsedSearchQuery = getTextQueryBaseComponent(q)
		}

		parsedMatchQuery = map[string]interface{}{
			q.Key: map[string]interface{}{
				MongoQueryOperatorMap[o]: q.Value,
			},
		}
	case QueryOperatorIn, QueryOperatorInLow, QueryOperatorTextLow, QueryOperatorText, QueryOperatorContainsLow, QueryOperatorContains:
		parsedSearchQuery = getTextQueryBaseComponent(q)
	case QueryOperatorNotIn, QueryOperatorNotInLow:
		parsedSearchQuery = turnTextQueryComponentToNot(getTextQueryBaseComponent(q))
	case QueryOperatorExists, QueryOperatorExistsLow:
		if _, ok := q.Value.(bool); !ok {
			return MongoQuery{}, MongoQuery{}, errors.Errorf("Value for 'exists' operator must be boolean. Got: %#v with value of type %T", q, q.Value)
		}

		if q.Value.(bool) == true {
			parsedSearchQuery = getTextQueryBaseComponent(q)
		} else {
			parsedSearchQuery = turnTextQueryComponentToNot(getTextQueryBaseComponent(q))
		}
	case QueryOperatorAnd, QueryOperatorAndLow:
		searchQueries, matchQueries, err := handleAndOrCasesForTextQuery(q)
		if err != nil {
			return MongoQuery{}, MongoQuery{}, err
		}

		if len(searchQueries) == 1 {
			parsedSearchQuery = searchQueries[0]
		} else if len(searchQueries) > 1 {
			parsedSearchQuery = textQueryCompoundWrapper(map[string]interface{}{TextQueryOperatorMust: searchQueries})
		}

		if len(matchQueries) == 1 {
			parsedMatchQuery = matchQueries[0]
		} else if len(matchQueries) > 1 {
			parsedMatchQuery = MongoQuery{
				MongoQueryOperatorMap[o]: matchQueries,
			}
		}

	case QueryOperatorOr, QueryOperatorOrLow:
		searchQueries, matchQueries, err := handleAndOrCasesForTextQuery(q)
		if err != nil {
			return MongoQuery{}, MongoQuery{}, err
		}

		if len(searchQueries) == 1 {
			parsedSearchQuery = searchQueries[0]
		} else if len(searchQueries) > 1 {
			parsedSearchQuery = textQueryCompoundWrapper(map[string]interface{}{TextQueryOperatorShould: searchQueries, TextQueryMinimumShouldMatch: MinimumShouldMatchValue})
		}

		if len(matchQueries) == 1 {
			parsedMatchQuery = matchQueries[0]
		} else if len(matchQueries) > 1 {
			parsedMatchQuery = MongoQuery{
				MongoQueryOperatorMap[o]: matchQueries,
			}
		}

	default:
		parsedSearchQuery = nil
		parsedMatchQuery = nil
		err = errors.Errorf("Invalid text query. Unsupported operator: %s", o).SetClass(errors.ClassBadInput)
	}

	return parsedSearchQuery, parsedMatchQuery, err
}

func getTextQueryBaseComponent(q Query) map[string]interface{} {
	if q.Operator == QueryOperatorExistsLow || q.Operator == QueryOperatorExists {
		return map[string]interface{}{
			QueryOperatorExistsLow: map[string]interface{}{
				TextQueryPathSection: q.Key,
			},
		}
	}

	if (q.Operator == QueryOperatorText || q.Operator == QueryOperatorTextLow) && q.Key == TextQueryKeyWildcard {
		queryValue := truncateValue(q.Value.(string), q.Key)
		return map[string]interface{}{
			TextQueryKeyWildcard: map[string]interface{}{
				TextQueryQuerySection:       fmt.Sprintf("%s%s", queryValue, TextQueryWildcardValueMatchAny),
				TextQueryPathSection:        map[string]interface{}{TextQueryKeyWildcard: TextQueryWildcardValueMatchAny},
				TextQueryAllowAnalyzedField: true,
			},
		}
	}

	if q.Operator == QueryOperatorIn || q.Operator == QueryOperatorInLow || q.Operator == QueryOperatorNotIn || q.Operator == QueryOperatorNotInLow {
		var valArrString []string
		switch v := q.Value.(type) {
		case []interface{}:
			for _, val := range v {
				queryValue := truncateValue(val.(string), q.Key)
				valArrString = append(valArrString, queryValue)
			}

			return map[string]interface{}{
				QueryOperatorTextLow: map[string]interface{}{
					TextQueryQuerySection: valArrString,
					TextQueryPathSection:  q.Key,
				},
			}
		case []string:
			for _, val := range v {
				queryValue := truncateValue(val, q.Key)
				valArrString = append(valArrString, queryValue)
			}

			return map[string]interface{}{
				QueryOperatorTextLow: map[string]interface{}{
					TextQueryQuerySection: valArrString,
					TextQueryPathSection:  q.Key,
				},
			}
		}

		return map[string]interface{}{
			QueryOperatorTextLow: map[string]interface{}{
				TextQueryQuerySection: q.Value,
				TextQueryPathSection:  q.Key,
			},
		}
	}

	queryValue := truncateValue(q.Value.(string), q.Key)
	return map[string]interface{}{
		QueryOperatorTextLow: map[string]interface{}{
			TextQueryQuerySection: queryValue,
			TextQueryPathSection:  q.Key,
		},
	}
}

func truncateValue(qValue, qKey string) string {
	// Data is indexed using nGram of 2 to 20, so we truncate query value to 20 chars
	// Except ipv6Addresses that is indexed for 2 to 39
	if _, ok := keysNotToShortValue[qKey]; !ok && len(qValue) > nGramLen {
		qValue = qValue[0:nGramLen]
	}

	return qValue
}

func turnTextQueryComponentToNot(qc map[string]interface{}) map[string]interface{} {
	return textQueryCompoundWrapper(map[string]interface{}{TextQueryOperatorMustNot: []map[string]interface{}{qc}})
}

func textQueryCompoundWrapper(qc map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{TextQueryOperatorCompound: qc}
}

func handleAndOrCasesForTextQuery(q Query) ([]MongoQuery, []MongoQuery, error) {
	var searchQueries []MongoQuery
	var matchQueries []MongoQuery
	for _, query := range q.Operands {
		parsedSearchComponent, parsedMatchComponent, err := recParseTextQueryToMongoQuery(query)
		if err != nil {
			return []MongoQuery{}, []MongoQuery{}, err
		}

		if len(parsedSearchComponent) > 0 {
			searchQueries = append(searchQueries, parsedSearchComponent)
		}

		if len(parsedMatchComponent) > 0 {
			matchQueries = append(matchQueries, parsedMatchComponent)
		}
	}

	return searchQueries, matchQueries, nil
}

// ParseTextQueryWithFacetsToMongoQuery transforms a Query and wanted ReportedFacets into a mongo fitting query
func ParseTextQueryWithFacetsToMongoQuery(q Query, facets ReportedFacets) (MongoQuery, MongoQuery, error) {
	parsedSearchQuery, parsedMatchQuery, err := ParseTextQueryToMongoQuery(q)
	if err != nil {
		return MongoQuery{}, MongoQuery{}, errors.Wrapf(err, "Failed to parse query with facets. Query=%+v", q)
	}

	parsedFacets := MongoQuery{}
	for _, ag := range facets.Aggregations {
		parsedFacets[ag.Key] = MongoQuery{
			FacetQueryTypeSection:       StringFacetType,
			TextQueryPathSection:        ag.Key,
			FacetQueryNumBucketsSection: facets.BucketNumber,
		}
	}

	var parsedFacetsSearchQuery MongoQuery
	if parsedSearchQuery != nil {
		parsedFacetsSearchQuery = MongoQuery{FacetQueryFacetSection: MongoQuery{
			FacetQueryOperatorSection: parsedSearchQuery,
			FacetQueryFacetsSection:   parsedFacets},
		}
	}

	return parsedFacetsSearchQuery, parsedMatchQuery, nil
}
