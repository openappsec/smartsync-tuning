package models

import (
	"encoding/json"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"openappsec.io/errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// query field constants
const (
	asterisk = "*"

	mainAttributesKeyIPv4 = "mainAttributes.ipv4Addresses"
	mainAttributesKeyIPv6 = "mainAttributes.ipv6Addresses"
)

// query operators
const (
	QueryOperatorAnd               = "AND"
	QueryOperatorAndLow            = "and"
	QueryOperatorOr                = "OR"
	QueryOperatorOrLow             = "or"
	QueryOperatorExists            = "EXISTS"
	QueryOperatorExistsLow         = "exists"
	QueryOperatorEquals            = "EQUALS"
	QueryOperatorEqualsLow         = "equals"
	QueryOperatorNotEquals         = "NOT_EQUALS"
	QueryOperatorNotEqualsLow      = "notEquals"
	QueryOperatorGTE               = "GREATER_THAN_EQUALS"
	QueryOperatorGTELow            = "greaterThanEquals"
	QueryOperatorLTE               = "LESS_THAN_EQUALS"
	QueryOperatorLTELow            = "lessThanEquals"
	QueryOperatorGT                = "GREATER_THAN"
	QueryOperatorGTLow             = "greaterThan"
	QueryOperatorLT                = "LESS_THAN"
	QueryOperatorLTLow             = "lessThan"
	QueryOperatorMatch             = "MATCH"
	QueryOperatorMatchLow          = "match"
	QueryOperatorStartsWith        = "STARTS_WITH"
	QueryOperatorStartsWithLow     = "startsWith"
	QueryOperatorContains          = "CONTAINS"
	QueryOperatorContainsLow       = "contains"
	QueryOperatorIn                = "IN"
	QueryOperatorInLow             = "in"
	QueryOperatorNotIn             = "NOT_IN"
	QueryOperatorNotInLow          = "notIn"
	IsWorkerContextField           = "isWorker"
	IndeedWorkerContextValue       = "ImAWorker"
	QueryOperatorRange             = "RANGE"
	QueryOperatorRangeLow          = "range"
	QueryOperatorElemMatchLow      = "elemMatch"
	QueryOperatorText              = "TEXT"
	QueryOperatorTextLow           = "text"
	TextQueryOperatorCompound      = "compound"
	TextQueryOperatorFilter        = "filter"
	TextQueryOperatorMust          = "must"
	TextQueryOperatorMustNot       = "mustNot"
	TextQueryOperatorShould        = "should"
	TextQueryPathSection           = "path"
	TextQueryQuerySection          = "query"
	TextQueryMinimumShouldMatch    = "minimumShouldMatch"
	MinimumShouldMatchValue        = 1
	TextQueryKeyWildcard           = "wildcard"
	TextQueryWildcardValueMatchAny = "*"
	TextQueryAllowAnalyzedField    = "allowAnalyzedField"
	FacetQueryFacetSection         = "facet"
	FacetQueryFacetsSection        = "facets"
	FacetQueryTypeSection          = "type"
	FacetQueryNumBucketsSection    = "numBuckets"
	FacetQueryOperatorSection      = "operator"
	StringFacetType                = "string"
)

// query and query result types
const (
	TypeReportedAssetQuery            = "models.ReportedAssetQuery"
	TypeReportedIntelQuery            = "models.ReportedIntelQuery"
	TypeIntelQueryV2                  = "models.IntelQueryV2"
	TypeQueryResponseAssets           = "models.QueryResponseAssets"
	TypeQueryResponseAssetCollections = "models.QueryResponseAssetCollections"
)

const (
	// CtxFieldKeyAgentBulkQuery is the key that indicates the context went through the agent bulk query handling
	CtxFieldKeyAgentBulkQuery = "agentBulkQuery"

	// CtxFieldKeyQueryParsed is the key that indicates the context went through the query parsing
	CtxFieldKeyQueryParsed = "queryParsed"

	// CtxFieldKeyDontUseCache indicates that the cache shouldn't be used if the key is found
	CtxFieldKeyDontUseCache = "dontUseCache"
)

// Projection is the type of projection option
type Projection map[string]int

// Query is the query API structure of the intelligence
type Query struct {
	Operator string      `json:"operator,omitempty"`
	Key      string      `json:"key,omitempty"`
	Value    interface{} `json:"value,omitempty"`
	Operands []Query     `json:"operands,omitempty"`
}

// Queries is a list of Query
type Queries []Query

// RefactorQueryStruct represents the refactored query and its values
type RefactorQueryStruct struct {
	RefactoredQuery  Query            `json:"refactoredQuery,omitempty"`
	IsIPQuery        bool             `json:"isIpQuery,omitempty"`
	SourcesFromQuery SourcesFromQuery `json:"sourcesFromQuery,omitempty"`
	Depth            int              `json:"depth,omitempty"`
}

// UnmarshalJSON implements the json.Unmarshaler interface. It unmarshalls a Query in the following manner:
// If Query.Key starts with mainAttributes && the value is array type:
//  1. If the array is []string --> it sorts it.
//  2. Otherwise --> returns an error bad input (since mainAttributes of type array can only be []string
//
// Else - it behaves as regular unmarshal does.
func (q *Query) UnmarshalJSON(b []byte) error {
	type tmpQuery struct {
		Operator string      `json:"operator,omitempty"`
		Key      string      `json:"key,omitempty"`
		Value    interface{} `json:"value,omitempty"`
		Operands []Query     `json:"operands,omitempty"`
	}

	var query tmpQuery
	if err := json.Unmarshal(b, &query); err != nil {
		return err
	}

	q.Operator = query.Operator
	q.Key = query.Key
	q.Value = query.Value
	q.Operands = query.Operands

	// If EQUALS query with MainAttributes as key and value is an array of strings --> sort it
	if q.Operator == QueryOperatorEquals && strings.HasPrefix(q.Key, FieldMainAttributes) && reflect.TypeOf(q.Value).Kind() == reflect.Slice {
		// Convert interface{} of type slice into []string
		var strArrMainAtt []string
		mainAttArray := reflect.ValueOf(q.Value)
		for i := 0; i < mainAttArray.Len(); i++ {
			// Type assert the value in the array is string, and if so, populate the strArrMainAtt
			str, ok := mainAttArray.Index(i).Interface().(string)
			if !ok {
				// We only allow for MainAttributes as string, []string or mix of the two.
				//If user queries mainAttributes with array as value, but it is not an array of strings --> it is a bad request
				return errors.Errorf("mainAttributes with an array type can contain only strings").SetClass(errors.ClassBadInput)
			}
			strArrMainAtt = append(strArrMainAtt, str)
		}

		sort.Strings(strArrMainAtt)
		q.Value = strArrMainAtt
	}

	return nil
}

// MatchAsset matches an asset to the give query returns true if a match occurs, false otherwise
func (q *Query) MatchAsset(a Asset) (bool, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return false, errors.Wrap(err, "Failed to convert asset to bytes")
	}
	c, err := gabs.ParseJSON(b)
	if err != nil {
		return false, errors.Wrap(err, "Failed to load asset bytes into gabs")
	}

	var match func(q *Query, c *gabs.Container) (bool, error)
	match = func(q *Query, c *gabs.Container) (bool, error) {
		if q.Operator == "" {
			return true, nil
		}

		o := q.Operator
		switch o {
		case QueryOperatorAnd, QueryOperatorAndLow:
			res := true
			for i := 0; i < len(q.Operands); i++ {
				r, err := match(&q.Operands[i], c)
				if err != nil {
					return false, err
				}
				res = res && r
			}
			return res, nil
		case QueryOperatorOr, QueryOperatorOrLow:
			res := false
			for i := 0; i < len(q.Operands); i++ {
				r, err := match(&q.Operands[i], c)
				if err != nil {
					return false, err
				}
				res = res || r
			}
			return res, nil
		case QueryOperatorNotIn, QueryOperatorNotInLow:
			assetData := c.Path(q.Key).Data()
			res := true
			arr, ok := interfaceToArrayOfInterfaces(q.Value)
			if !ok {
				return false, errors.Errorf("NotIn query with value of type %T is not supported", q.Value)
			}

			for _, v := range arr {
				if reflect.DeepEqual(v, assetData) {
					res = false
				}
			}
			return res, nil
		case QueryOperatorIn, QueryOperatorInLow:
			assetData := c.Path(q.Key).Data()
			res := false
			arr, ok := interfaceToArrayOfInterfaces(q.Value)
			if !ok {
				return false, errors.Errorf("In query with value of type %T is not supported", q.Value)
			}

		queryLoop:
			for _, v := range arr {
				assetDataList, ok := assetData.([]interface{})
				if !ok {
					if reflect.DeepEqual(v, assetData) {
						res = true
						break
					}
					continue
				}
				for _, assetVal := range assetDataList {
					if reflect.DeepEqual(v, assetVal) {
						res = true
						break queryLoop
					}
				}
			}

			return res, nil
		case QueryOperatorNotEquals, QueryOperatorNotEqualsLow:
			return !reflect.DeepEqual(q.Value, c.Path(q.Key).Data()), nil
		case QueryOperatorEquals, QueryOperatorEqualsLow:
			// if the key is ipv4Addresses or ipv6Addresses
			if q.Key == mainAttributesKeyIPv4 || q.Key == mainAttributesKeyIPv6 || q.Key == AttributesIPv4Addresses || q.Key == AttributesIPv6Addresses {
				return matchAssetEqualsIpv4Ipv6(q, c)
			}

			return reflect.DeepEqual(q.Value, c.Path(q.Key).Data()), nil
		case QueryOperatorStartsWith, QueryOperatorStartsWithLow:
			assetData, ok := c.Path(q.Key).Data().(string)
			if !ok {
				return false, nil // not an error, given a regex op on a non string asset field we declare a mismatch
			}
			prefix, ok := q.Value.(string)
			if !ok {
				return false, errors.Errorf("Invalid %s value given (%s)", QueryOperatorStartsWith, q.Value).SetClass(errors.ClassBadInput)
			}
			return strings.HasPrefix(assetData, prefix), nil
		case QueryOperatorContains, QueryOperatorContainsLow:
			assetData, ok := c.Path(q.Key).Data().(string)
			if !ok {
				return false, nil // not an error, given a regex op on a non string asset field we declare a mismatch
			}
			contain, ok := q.Value.(string)
			if !ok {
				return false, errors.Errorf("Invalid %s value given (%s)", QueryOperatorContains, q.Value).SetClass(errors.ClassBadInput)
			}
			return strings.Contains(assetData, contain), nil
		case QueryOperatorMatch, QueryOperatorMatchLow:
			assetData, ok := c.Path(q.Key).Data().(string)
			if !ok {
				return false, nil // not an error, given a regex op on a non string asset field we declare a mismatch
			}
			regex, ok := q.Value.(string)
			if !ok {
				return false, errors.Errorf("Invalid %s value given (%s)", QueryOperatorMatch, q.Value).SetClass(errors.ClassBadInput)
			}
			res, err := regexp.Match(regex, []byte(assetData))
			if err != nil {
				return false, errors.Wrapf(err, "Invalid %s value given (%s)", QueryOperatorMatch, q.Value).SetClass(errors.ClassBadInput)
			}
			return res, nil
		case QueryOperatorExists, QueryOperatorExistsLow:
			return q.Value == (c.Path(q.Key).Data() != nil), nil
		case QueryOperatorGT, QueryOperatorGTLow:
			val, err := q.castQueryValueToFloat64()
			if err != nil {
				return false, err
			}

			assetData, ok := c.Path(q.Key).Data().(float64)
			if !ok {
				return false, nil // not a number, can't do GT operation, declare mismatch
			}

			return assetData > val, nil
		case QueryOperatorLT, QueryOperatorLTLow:
			val, err := q.castQueryValueToFloat64()
			if err != nil {
				return false, err
			}

			assetData, ok := c.Path(q.Key).Data().(float64)
			if !ok {
				return false, nil // not a number, can't do LT operation, declare mismatch
			}

			return assetData < val, nil
		case QueryOperatorGTE, QueryOperatorGTELow:
			val, err := q.castQueryValueToFloat64()
			if err != nil {
				val, ok := q.Value.(string)
				if !ok {
					return false, errors.Wrap(err, "Greater then equals operator should be a number or a string")
				}

				assetData, ok := c.Path(q.Key).Data().(string)
				if !ok {
					return false, nil // not a number, can't do GTE operation, declare mismatch
				}

				return assetData >= val, nil
			}

			assetData, ok := c.Path(q.Key).Data().(float64)
			if !ok {
				return false, nil // not a number, can't do GTE operation, declare mismatch
			}

			return assetData >= val, nil
		case QueryOperatorLTE, QueryOperatorLTELow:
			val, err := q.castQueryValueToFloat64()
			if err != nil {
				val, ok := q.Value.(string)
				if !ok {
					return false, errors.Wrap(err, "Greater then equals operator should be a number or a string")
				}

				assetData, ok := c.Path(q.Key).Data().(string)
				if !ok {
					return false, nil // not a number, can't do GTE operation, declare mismatch
				}

				return assetData <= val, nil
			}

			assetData, ok := c.Path(q.Key).Data().(float64)
			if !ok {
				return false, nil // not a number, can't do GTE operation, declare mismatch
			}

			return assetData >= val, nil
		case QueryOperatorRange, QueryOperatorRangeLow:
			return matchAssetToRangeOperator(*q, a)
		case QueryOperatorText, QueryOperatorTextLow:
			contain, ok := q.Value.(string)
			if !ok {
				return false, errors.Errorf("Value in query for %s operator must be of type string (key=%s, value=%v)", QueryOperatorText, q.Key, q.Value).SetClass(errors.ClassBadInput)
			}

			if q.Key != TextQueryKeyWildcard {
				assetData, ok := c.Path(q.Key).Data().(string)
				if !ok {
					return false, errors.Errorf("Value of key %s in asset %+v is expected to be of type string (since matching to query operator %s)", q.Key, a, QueryOperatorText).SetClass(errors.ClassBadInput)
				}

				return strings.Contains(assetData, contain), nil
			}

			// free text search
			marshaledAss, err := json.Marshal(a)
			if err != nil {
				return false, errors.Wrapf(err, "Failed to check if asset matches free-text search query").SetClass(errors.ClassInternal)
			}

			return strings.Contains(string(marshaledAss), contain), nil
		default:
			return false, errors.Errorf("Invalid query. Unknown operator: %s", o).SetClass(errors.ClassBadInput)
		}
	}

	return match(q, c)
}

func matchAssetToRangeOperator(q Query, a Asset) (bool, error) {
	var minVal, maxVal interface{}
	switch v := q.Value.(type) {
	case []string:
		if len(v) != 2 {
			return false, errors.Errorf("Range operator value should be an array of length 2")
		}

		minVal = v[0]
		maxVal = v[1]
	case []float64:
		if len(v) != 2 {
			return false, errors.Errorf("Range operator value should be an array of length 2")
		}

		minVal = int(v[0])
		maxVal = int(v[1])
	case []int:
		if len(v) != 2 {
			return false, errors.Errorf("Range operator value should be an array of length 2")
		}

		minVal = v[0]
		maxVal = v[1]
	case []interface{}:
		if len(v) != 2 {
			return false, errors.Errorf("Range operator value should be an array of length 2")
		}

		switch e := v[0].(type) {
		case string:
			minVal = e
		default:
			var ok bool
			minVal, ok = interfaceToInt(v[1])
			if !ok {
				return false, errors.Errorf("Range operator value should be a string or int")
			}
		}

		switch e := v[1].(type) {
		case string:
			maxVal = e
		default:
			var ok bool
			maxVal, ok = interfaceToInt(v[1])
			if !ok {
				return false, errors.Errorf("Range operator value should be a string or int")
			}
		}
	default:
		return false, errors.Errorf("Range operator value should be an array of string, int, float64 or interface{}")
	}

	switch q.Key {
	// We enrich the asset before we do the match to the query, so the range match should be with the range field in the asset
	case AttributesIPv4AddressesRange:
		assertedMinVal, ok := minVal.(string)
		if !ok {
			return false, errors.Errorf("Failed to assert minVal (%#v) to be string, got type %t", minVal, minVal)
		}

		queryMinIP, err := StringToIntIPv4(assertedMinVal)
		if err != nil {
			return false, err
		}

		assertedMaxVal, ok := maxVal.(string)
		if !ok {
			return false, errors.Errorf("Failed to assert maxVal (%#v) to be string, got type %t", maxVal, maxVal)
		}

		queryMaxIP, err := StringToIntIPv4(assertedMaxVal)
		if err != nil {
			return false, err
		}

		_, okIPV4AddressesRange := a.Attributes[ipv4AddressesRange]
		if okIPV4AddressesRange {
			var assMinIP, assMaxIP int
			var ipv4AddressesRangeAttStruct RangeMaps
			switch castedRanges := a.Attributes[ipv4AddressesRange].(type) {
			case RangeMaps:
				ipv4AddressesRangeAttStruct = castedRanges
			case []interface{}:
				for _, ranges := range castedRanges {
					switch castedRange := ranges.(type) {
					case RangeMap:
						ipv4AddressesRangeAttStruct = append(ipv4AddressesRangeAttStruct, castedRange)
					case map[string]interface{}:
						ipv4AddressesRangeAttStruct = append(ipv4AddressesRangeAttStruct, castedRange)
					default:
						return false, errors.Errorf("Failed to assert attributes.%s as type map[string]interface{} or type RangeMap while matching asset to query, got %#v", ipv4AddressesRange, a.Attributes[ipv4AddressesRange]).SetClass(errors.ClassBadInput)
					}
				}
			default:
				return false, errors.Errorf("Failed to assert attributes.%s as type []interface{} or type RangeMaps while matching asset to query, got %#v", ipv4AddressesRange, a.Attributes[ipv4AddressesRange]).SetClass(errors.ClassBadInput)
			}

			for _, ipRange := range ipv4AddressesRangeAttStruct {
				stringMinIP, ok := ipRange[Min].(string)
				if !ok {
					return false, errors.Errorf("Failed to assert %s value as type string, got %#v", AttributesIPv4AddressesRangeMin, ipRange[Min]).SetClass(errors.ClassBadInput)
				}

				assMinIP, err = StringToIntIPv4(stringMinIP)
				if err != nil {
					return false, err
				}

				stringMaxIP, ok := ipRange[Max].(string)
				if !ok {
					return false, errors.Errorf("Failed to assert %s value as type string, got %#v", AttributesIPv4AddressesRangeMax, ipRange[Max]).SetClass(errors.ClassBadInput)
				}

				assMaxIP, err = StringToIntIPv4(stringMaxIP)
				if err != nil {
					return false, err
				}

				// find intersect between asset range and query range
				// assets min is smaller or equals query min and assets max is bigger or similar to query min
				if assMinIP <= queryMinIP && assMaxIP >= queryMinIP {
					return true, nil
				}

				// assets min is smaller or equals to query max and asset max is bigger or equals to query max
				if assMinIP <= queryMaxIP && assMaxIP >= queryMaxIP {
					return true, nil
				}

				// asset range is inside the query range
				if assMinIP >= queryMinIP && assMaxIP <= queryMaxIP {
					return true, nil
				}
			}
		}
	case AttributesIPv6AddressesRange:
		const equals = 0
		const lessThan = -1
		const greaterThan = 1
		assertedMinVal, ok := minVal.(string)
		if !ok {
			return false, errors.Errorf("Failed to assert minVal (%#v) to be string, got type %T", minVal, minVal)
		}

		queryMinIP, err := StringToIntIPv6(assertedMinVal)
		if err != nil {
			return false, err
		}

		assertedMaxVal, ok := maxVal.(string)
		if !ok {
			return false, errors.Errorf("Failed to assert maxVal (%#v) to be string, got type %T", maxVal, maxVal)
		}
		queryMaxIP, err := StringToIntIPv6(assertedMaxVal)
		if err != nil {
			return false, err
		}

		_, okIPV6AddressesRange := a.Attributes[ipv6AddressesRange]
		if okIPV6AddressesRange {
			var assMinIP, assMaxIP *big.Int
			var ipv6AddressesRangeAttStruct RangeMaps
			switch castedRanges := a.Attributes[ipv6AddressesRange].(type) {
			case RangeMaps:
				ipv6AddressesRangeAttStruct = castedRanges
			case []interface{}:
				for _, ranges := range castedRanges {
					switch castedRange := ranges.(type) {
					case RangeMap:
						ipv6AddressesRangeAttStruct = append(ipv6AddressesRangeAttStruct, castedRange)
					case map[string]interface{}:
						ipv6AddressesRangeAttStruct = append(ipv6AddressesRangeAttStruct, castedRange)
					default:
						return false, errors.Errorf("Failed to assert attributes.%s as type map[string]interface{} or type RangeMap while matching asset to query, got %#v", ipv6AddressesRange, a.Attributes[ipv6AddressesRange]).SetClass(errors.ClassBadInput)
					}
				}
			default:
				return false, errors.Errorf("Failed to assert attributes.%s as type []interface{} or type RangeMaps while matching asset to query, got %#v", ipv6AddressesRange, a.Attributes[ipv6AddressesRange]).SetClass(errors.ClassBadInput)
			}

			for _, ipRange := range ipv6AddressesRangeAttStruct {
				stringMinIP, ok := ipRange[Min].(string)
				if !ok {
					return false, errors.Errorf("Failed to assert %s value as type string, got %#v", AttributesIPv6AddressesRangeMin, ipRange[Min]).SetClass(errors.ClassBadInput)
				}

				assMinIP, err = StringToIntIPv6(stringMinIP)
				if err != nil {
					return false, err
				}

				stringMaxIP, ok := ipRange[Max].(string)
				if !ok {
					return false, errors.Errorf("Failed to assert %s value as type string, got %#v", AttributesIPv6AddressesRangeMax, ipRange[Max]).SetClass(errors.ClassBadInput)
				}

				assMaxIP, err = StringToIntIPv6(stringMaxIP)
				if err != nil {
					return false, err
				}

				// find intersect between asset range and query range
				// assets min is smaller or equals query min and assets max is bigger or similar to query min

				assMinQueryMinCmp := assMinIP.Cmp(queryMinIP)
				assMaxQueryMinCmp := assMaxIP.Cmp(queryMinIP)
				if (assMinQueryMinCmp == lessThan || assMinQueryMinCmp == equals) && (assMaxQueryMinCmp == greaterThan || assMaxQueryMinCmp == equals) {
					return true, nil
				}

				assMinQueryMaxCmp := assMinIP.Cmp(queryMaxIP)
				assMaxQueryMaxCmp := assMaxIP.Cmp(queryMaxIP)
				// assets min is smaller or equals to query max and asset max is bigger or equals to query max
				if (assMinQueryMaxCmp == lessThan || assMinQueryMaxCmp == equals) && (assMaxQueryMaxCmp == greaterThan || assMaxQueryMaxCmp == equals) {
					return true, nil
				}

				// asset range is inside the query range
				if (assMinQueryMinCmp == greaterThan || assMinQueryMinCmp == equals) && (assMaxQueryMaxCmp == lessThan || assMaxQueryMaxCmp == equals) {
					return true, nil
				}
			}
		}
	case AttributesPortsRange:
		queryMinPort, ok := minVal.(int)
		if !ok {
			return false, errors.Errorf("Failed to assert minVal (%#v) to be int, got type %T", minVal, minVal)
		}

		queryMaxPort, ok := maxVal.(int)
		if !ok {
			return false, errors.Errorf("Failed to assert maxVal (%#v) to be int, got type %T", maxVal, maxVal)
		}

		_, okPortsRange := a.Attributes[portsRange]
		if okPortsRange {
			var assMinPort, assMaxPort int
			var portsRangeAttStruct RangeMaps
			switch castedRanges := a.Attributes[portsRange].(type) {
			case RangeMaps:
				portsRangeAttStruct = castedRanges
			case []interface{}:
				for _, ranges := range castedRanges {
					switch castedRange := ranges.(type) {
					case RangeMap:
						portsRangeAttStruct = append(portsRangeAttStruct, castedRange)
					case map[string]interface{}:
						portsRangeAttStruct = append(portsRangeAttStruct, castedRange)
					default:
						return false, errors.Errorf("Failed to assert attributes.%s as type map[string]interface{} or type RangeMap while matching asset to query, got %#v", portsRange, a.Attributes[portsRange]).SetClass(errors.ClassBadInput)
					}
				}
			default:
				return false, errors.Errorf("Failed to assert attributes.%s as type []interface{} or type RangeMaps while matching asset to query, got %#v", portsRange, a.Attributes[portsRange]).SetClass(errors.ClassBadInput)
			}

			for _, portRange := range portsRangeAttStruct {
				assMinPort, ok = interfaceToInt(portRange[Min])
				if !ok {
					return false, errors.Errorf("Failed to assert %s value as type int, got %#v", AttributesPortsRange, portRange[Min]).SetClass(errors.ClassBadInput)
				}

				assMaxPort, ok = interfaceToInt(portRange[Max])
				if !ok {
					return false, errors.Errorf("Failed to assert %s value as type int, got %#v", AttributesIPv4AddressesRangeMax, portRange[Max]).SetClass(errors.ClassBadInput)
				}

				// find intersect between asset range and query range
				// assets min is smaller or equals query min and assets max is bigger or similar to query min
				if assMinPort <= queryMinPort && assMaxPort >= queryMinPort {
					return true, nil
				}

				// assets min is smaller or equals to query max and asset max is bigger or equals to query max
				if assMinPort <= queryMaxPort && assMaxPort >= queryMaxPort {
					return true, nil
				}

				// asset range is inside the query range
				if assMinPort >= queryMinPort && assMaxPort <= queryMaxPort {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// RefactorNonTextQuery recursively goes over the query to check if it is about
// either: AttributesIPv4Addresses, AttributesIPv6Addresses or AttributesPorts, and if so, adds range to the query.
// Checks if it hase sourceId in the query and if so adds to the source id from query maps
// NOTE! q.Operands can be changed during this function
func RefactorNonTextQuery(q Query, sourcesFromQuery SourcesFromQuery) (RefactorQueryStruct, error) {
	var match func(q Query, depth int, sourcesFromQuery SourcesFromQuery) (RefactorQueryStruct, error)
	depth := 0
	match = func(q Query, depth int, sourcesFromQuery SourcesFromQuery) (RefactorQueryStruct, error) {
		if q.Operator == "" {
			return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
		}

		var err error
		o := q.Operator
		switch o {
		case QueryOperatorAnd, QueryOperatorAndLow:
			fallthrough
		case QueryOperatorOr, QueryOperatorOrLow:
			isIPQuery := false
			maxDepth := depth
			for i := 0; i < len(q.Operands); i++ {
				refactoredQueryVars, err := match(q.Operands[i], depth+1, sourcesFromQuery)
				if err != nil {
					return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, err
				}

				if refactoredQueryVars.Depth > maxDepth {
					maxDepth = refactoredQueryVars.Depth
				}

				if refactoredQueryVars.IsIPQuery {
					q.Operands[i] = refactoredQueryVars.RefactoredQuery
					isIPQuery = true
				}

				sourcesFromQuery = refactoredQueryVars.SourcesFromQuery
			}

			return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: isIPQuery, SourcesFromQuery: sourcesFromQuery, Depth: maxDepth}, nil
		case QueryOperatorEquals, QueryOperatorEqualsLow:
			depth++
			switch q.Key {
			case AttributesIPv4Addresses, AttributesIPv6Addresses, AttributesPorts:
				// create the equals and range query
				q, err = createIPAddressesRangeQuery(q)
				if err != nil {
					return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, err
				}

				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: true, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			case FieldSourceID:
				srcIDStr, ok := q.Value.(string)
				if !ok {
					return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into string", q.Value)
				}

				sourcesFromQuery.SourcesToQuery[srcIDStr] = struct{}{}
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			default:
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			}
		case QueryOperatorNotEquals, QueryOperatorNotEqualsLow:
			depth++
			switch q.Key {
			case FieldSourceID:
				srcIDStr, ok := q.Value.(string)
				if !ok {
					return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into string", q.Value)
				}

				sourcesFromQuery.SourcesNotToQuery[srcIDStr] = struct{}{}
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			default:
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			}
		case QueryOperatorMatch, QueryOperatorMatchLow,
			QueryOperatorStartsWith, QueryOperatorStartsWithLow,
			QueryOperatorContains, QueryOperatorContainsLow,
			QueryOperatorGT, QueryOperatorGTLow,
			QueryOperatorLT, QueryOperatorLTLow,
			QueryOperatorGTE, QueryOperatorGTELow,
			QueryOperatorLTE, QueryOperatorLTELow,
			QueryOperatorRange, QueryOperatorRangeLow:
			depth++
			return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
		case QueryOperatorIn, QueryOperatorInLow:
			depth++
			switch q.Key {
			case AttributesIPv4Addresses, AttributesIPv6Addresses, AttributesPorts:
				// create the equals and range query
				q, err = createIPAddressesRangeQuery(q)
				if err != nil {
					return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, err
				}

				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: true, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			case FieldSourceID:
				interfaceArray, ok := q.Value.([]interface{})
				if !ok {
					return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into %s", q.Value, typeInterfaceArray)
				}
				for _, srcID := range interfaceArray {
					srcIDStr, ok := srcID.(string)
					if !ok {
						return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into string", srcID)
					}
					sourcesFromQuery.SourcesToQuery[srcIDStr] = struct{}{}
				}
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			default:
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			}
		case QueryOperatorNotIn, QueryOperatorNotInLow:
			depth++
			switch q.Key {
			case FieldSourceID:
				interfaceArray, ok := q.Value.([]interface{})
				if !ok {
					return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into %s", q.Value, typeInterfaceArray)
				}
				for _, srcID := range interfaceArray {
					srcIDStr, ok := srcID.(string)
					if !ok {
						return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into string", q.Value)
					}

					sourcesFromQuery.SourcesNotToQuery[srcIDStr] = struct{}{}
				}
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			default:
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			}
		default:
			return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Invalid query. Unknown operator: %s", o).SetClass(errors.ClassBadInput)
		}
	}

	return match(q, depth, sourcesFromQuery)
}

// RefactorTextQuery recursively goes over the query
// Checks if it hase sourceId in the query and if so adds to the source id from query maps
// NOTE! q.Operands can be changed during this function
func RefactorTextQuery(q Query, sourcesFromQuery SourcesFromQuery) (RefactorQueryStruct, error) {
	var match func(q Query, depth int, sourcesFromQuery SourcesFromQuery) (RefactorQueryStruct, error)
	depth := 0
	match = func(q Query, depth int, sourcesFromQuery SourcesFromQuery) (RefactorQueryStruct, error) {
		if q.Operator == "" {
			return RefactorQueryStruct{RefactoredQuery: q, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
		}

		o := q.Operator
		switch o {
		case QueryOperatorAnd, QueryOperatorAndLow:
			fallthrough
		case QueryOperatorOr, QueryOperatorOrLow:
			maxDepth := depth
			for i := 0; i < len(q.Operands); i++ {
				refactoredQueryVars, err := match(q.Operands[i], depth+1, sourcesFromQuery)
				if err != nil {
					return RefactorQueryStruct{RefactoredQuery: Query{}, SourcesFromQuery: sourcesFromQuery, Depth: depth}, err
				}

				if refactoredQueryVars.Depth > maxDepth {
					maxDepth = refactoredQueryVars.Depth
				}

				sourcesFromQuery = refactoredQueryVars.SourcesFromQuery
			}

			return RefactorQueryStruct{RefactoredQuery: q, SourcesFromQuery: sourcesFromQuery, Depth: maxDepth}, nil
		case QueryOperatorEquals, QueryOperatorEqualsLow, QueryOperatorText, QueryOperatorTextLow:
			depth++
			switch q.Key {
			case FieldSourceID:
				srcIDStr, ok := q.Value.(string)
				if !ok {
					return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into string", q.Value)
				}

				sourcesFromQuery.SourcesToQuery[srcIDStr] = struct{}{}
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			default:
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			}
		case QueryOperatorNotEquals, QueryOperatorNotEqualsLow:
			depth++
			switch q.Key {
			case FieldSourceID:
				srcIDStr, ok := q.Value.(string)
				if !ok {
					return RefactorQueryStruct{RefactoredQuery: Query{}, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into string", q.Value)
				}

				sourcesFromQuery.SourcesNotToQuery[srcIDStr] = struct{}{}
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			default:
				return RefactorQueryStruct{RefactoredQuery: q, IsIPQuery: false, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			}
		case QueryOperatorMatch, QueryOperatorMatchLow,
			QueryOperatorStartsWith, QueryOperatorStartsWithLow,
			QueryOperatorContains, QueryOperatorContainsLow,
			QueryOperatorGT, QueryOperatorGTLow,
			QueryOperatorLT, QueryOperatorLTLow,
			QueryOperatorGTE, QueryOperatorGTELow,
			QueryOperatorLTE, QueryOperatorLTELow,
			QueryOperatorRange, QueryOperatorRangeLow:
			depth++
			return RefactorQueryStruct{RefactoredQuery: q, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
		case QueryOperatorIn, QueryOperatorInLow:
			depth++
			switch q.Key {
			case FieldSourceID:
				interfaceArray, ok := q.Value.([]interface{})
				if !ok {
					return RefactorQueryStruct{RefactoredQuery: Query{}, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into %s", q.Value, typeInterfaceArray)
				}
				for _, srcID := range interfaceArray {
					srcIDStr, ok := srcID.(string)
					if !ok {
						return RefactorQueryStruct{RefactoredQuery: Query{}, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into string", srcID)
					}
					sourcesFromQuery.SourcesToQuery[srcIDStr] = struct{}{}
				}
				return RefactorQueryStruct{RefactoredQuery: q, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			default:
				return RefactorQueryStruct{RefactoredQuery: q, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			}
		case QueryOperatorNotIn, QueryOperatorNotInLow:
			depth++
			switch q.Key {
			case FieldSourceID:
				interfaceArray, ok := q.Value.([]interface{})
				if !ok {
					return RefactorQueryStruct{RefactoredQuery: Query{}, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into %s", q.Value, typeInterfaceArray)
				}
				for _, srcID := range interfaceArray {
					srcIDStr, ok := srcID.(string)
					if !ok {
						return RefactorQueryStruct{RefactoredQuery: Query{}, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Failed to convert value %+v into string", q.Value)
					}

					sourcesFromQuery.SourcesNotToQuery[srcIDStr] = struct{}{}
				}
				return RefactorQueryStruct{RefactoredQuery: q, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			default:
				return RefactorQueryStruct{RefactoredQuery: q, SourcesFromQuery: sourcesFromQuery, Depth: depth}, nil
			}
		default:
			return RefactorQueryStruct{RefactoredQuery: Query{}, SourcesFromQuery: sourcesFromQuery, Depth: depth}, errors.Errorf("Invalid query. Unknown operator: %s", o).SetClass(errors.ClassBadInput)
		}
	}

	return match(q, depth, sourcesFromQuery)
}

func createIPAddressesRangeQuery(q Query) (Query, error) {
	keyRange := q.Key + Range

	o := q.Operator
	var newQ Query
	switch o {
	case QueryOperatorEquals, QueryOperatorEqualsLow:
		newQ.Operator = QueryOperatorOrLow

		var operations Queries
		operation := Query{Operator: QueryOperatorEqualsLow, Key: q.Key, Value: q.Value}
		operations = append(operations, operation)

		operation = Query{
			Operator: QueryOperatorRangeLow,
			Key:      keyRange,
			Value:    []interface{}{q.Value, q.Value},
		}
		operations = append(operations, operation)
		newQ.Operands = operations
	case QueryOperatorIn, QueryOperatorInLow:
		newQ.Operator = QueryOperatorOrLow

		var operations Queries
		operation := Query{Operator: QueryOperatorInLow, Key: q.Key, Value: q.Value}
		operations = append(operations, operation)

		operationArray := Query{Operator: QueryOperatorOrLow}
		interfaceArray, ok := q.Value.([]interface{})
		if !ok {
			return Query{}, errors.Errorf("Failed to convert value %+v into %s", q.Value, typeInterfaceArray)
		}

		var operationsForArray Queries
		for _, element := range interfaceArray {
			operation = Query{
				Operator: QueryOperatorRangeLow,
				Key:      keyRange,
				Value:    []interface{}{element, element},
			}
			operationsForArray = append(operationsForArray, operation)
		}

		operationArray.Operands = operationsForArray
		operations = append(operations, operationArray)
		newQ.Operands = operations
	}

	return newQ, nil
}

func (q *Query) castQueryValueToFloat64() (float64, error) {
	var val float64
	switch v := q.Value.(type) {
	case int:
		val = float64(v)
	case float64:
		val = v
	default:
		return 0, errors.Errorf("Invalid %s value given (%s)", q.Operator, q.Value).SetClass(errors.ClassBadInput)
	}

	return val, nil
}

func matchAssetEqualsIpv4Ipv6(q *Query, c *gabs.Container) (bool, error) {
	// for ipv4 & ipv6, main attributes and attribute should be a list
	assetData := c.Path(q.Key).Data()
	assetDataList, ok := assetData.([]interface{})
	if !ok {
		return false, nil
	}

	if _, ok := q.Value.(string); ok {
		// convert assetDataList from []interface to []string
		assetDataStrList := make([]string, 0)
		for _, ass := range assetDataList {
			if assStr, ok := ass.(string); ok {
				assetDataStrList = append(assetDataStrList, assStr)
			}
		}

		queryIP := q.Value.(string)
		for _, ip := range assetDataStrList {
			if ip == queryIP {
				return true, nil
			}
		}

		return false, nil
	}

	qValList, ok := q.Value.([]string)
	if !ok {
		return false, nil
	}

	// convert assetDataList from []interface to []string
	assetDataStrList := make([]string, 0)
	for _, ass := range assetDataList {
		if assStr, ok := ass.(string); ok {
			assetDataStrList = append(assetDataStrList, assStr)
		}
	}

	sort.Slice(qValList, func(i, j int) bool { return qValList[i] < qValList[j] })
	sort.Slice(assetDataStrList, func(i, j int) bool { return assetDataStrList[i] < assetDataStrList[j] })

	if len(qValList) != len(assetDataStrList) {
		return false, nil
	}

	for i, v := range qValList {
		if v != assetDataStrList[i] {
			return false, nil
		}
	}

	return true, nil
}

// MatchQueryToDataMapMatcher matches an intel query to external source dataMap matcher part. returns true if finds a match, false otherwise
func (q *Query) MatchQueryToDataMapMatcher(matcher Matcher) (bool, error) {
	o := q.Operator
	switch o {
	case QueryOperatorAnd, QueryOperatorAndLow:
		fallthrough
	case QueryOperatorOr, QueryOperatorOrLow:
		for i := 0; i < len(q.Operands); i++ {
			res, err := (&q.Operands[i]).MatchQueryToDataMapMatcher(matcher)
			if err != nil {
				return false, err
			}
			if res {
				return true, nil
			}
		}
		return false, nil
	case QueryOperatorEquals, QueryOperatorEqualsLow:
		val, ok := matcher[q.Key]
		if !ok {
			return false, nil
		}
		// TODO think if we need to check something but string or []string
		queryVal, ok := q.Value.(string)
		if ok && (val == asterisk || val == queryVal) {
			return true, nil
		}

		queryValList, ok := q.Value.([]string)
		if !ok {
			return false, nil
		}

		if val == asterisk {
			return true, nil
		}

		for _, qVal := range queryValList {
			if qVal == val {
				return true, nil
			}
		}

		return false, nil
	case QueryOperatorExists, QueryOperatorExistsLow:
		_, ok := matcher[q.Key]
		if ok {
			return true, nil
		}
		return false, nil
	case QueryOperatorIn, QueryOperatorInLow:
		val, ok := matcher[q.Key]
		if !ok {
			return false, nil
		}
		if val == asterisk {
			return true, nil
		}
		queryVal, ok := q.Value.([]interface{})
		if ok && isMatchInArray(queryVal, val) {
			return true, nil
		}
		return false, nil
	case QueryOperatorMatch, QueryOperatorMatchLow,
		QueryOperatorNotIn, QueryOperatorNotInLow,
		QueryOperatorNotEquals, QueryOperatorNotEqualsLow,
		QueryOperatorStartsWith, QueryOperatorStartsWithLow,
		QueryOperatorContains, QueryOperatorContainsLow,
		QueryOperatorGT, QueryOperatorGTLow,
		QueryOperatorLT, QueryOperatorLTLow,
		QueryOperatorGTE, QueryOperatorGTELow,
		QueryOperatorLTE, QueryOperatorLTELow,
		QueryOperatorRange, QueryOperatorRangeLow:
		val, ok := matcher[q.Key]
		if !ok {
			return false, nil
		}

		if val == asterisk {
			return true, nil
		}
		return false, nil
	case QueryOperatorText, QueryOperatorTextLow:
		if q.Key == TextQueryKeyWildcard {
			// If it's a text query with wiled card - the auxiliary should know how to answer the query
			return true, nil
		}

		val, ok := matcher[q.Key]
		if !ok {
			return false, nil
		}

		if val == asterisk {
			return true, nil
		}
		return false, nil
	default:
		return false, errors.Errorf("Invalid query. Unknown operator: %s", o).SetClass(errors.ClassBadInput)
	}
}

func isMatchInArray(inArr []interface{}, matcherVal string) bool {
	for _, val := range inArr {
		// TODO think if we need to check something but string
		strVal, ok := val.(string)
		if !ok {
			continue
		}
		if strVal == matcherVal {
			return true
		}
	}
	return false
}

// ExtractAssetTypeFields extract all the fields that identify asset type from the query.
// The supported operators in the fields search are only: AND, EQUALS.
func (q *Query) ExtractAssetTypeFields() (AssetTypeFields, error) {
	o := q.Operator
	switch o {
	case QueryOperatorAnd, QueryOperatorAndLow:
		assetTypeFields := AssetTypeFields{}
		for i := 0; i < len(q.Operands); i++ {
			for i := 0; i < len(q.Operands); i++ {
				resFields, err := (&q.Operands[i]).ExtractAssetTypeFields()
				if err != nil {
					return AssetTypeFields{}, err
				}

				assetTypeFields.MergeAssetTypeFields(resFields)
			}
		}

		return assetTypeFields, nil
	case QueryOperatorEquals, QueryOperatorEqualsLow:
		assetTypeFields := extractAssetTypeFieldsEqualsOperator(q)
		return assetTypeFields, nil
	case QueryOperatorMatch, QueryOperatorMatchLow,
		QueryOperatorOr, QueryOperatorOrLow,
		QueryOperatorIn, QueryOperatorInLow,
		QueryOperatorNotIn, QueryOperatorNotInLow,
		QueryOperatorNotEquals, QueryOperatorNotEqualsLow,
		QueryOperatorStartsWith, QueryOperatorStartsWithLow,
		QueryOperatorContains, QueryOperatorContainsLow,
		QueryOperatorExists, QueryOperatorExistsLow,
		QueryOperatorGT, QueryOperatorGTLow,
		QueryOperatorLT, QueryOperatorLTLow,
		QueryOperatorGTE, QueryOperatorGTELow,
		QueryOperatorLTE, QueryOperatorLTELow,
		QueryOperatorRange, QueryOperatorRangeLow,
		QueryOperatorText, QueryOperatorTextLow:
		return AssetTypeFields{}, nil
	default:
		return AssetTypeFields{}, errors.Errorf("Invalid query. Unknown operator: %s", o).SetClass(errors.ClassBadInput)
	}
}

// extractAssetTypeFieldsEqualsOperator extracts the asset type fields from the query EQUAL operator
func extractAssetTypeFieldsEqualsOperator(q *Query) AssetTypeFields {
	assetTypeFields := AssetTypeFields{}
	switch q.Key {
	case assetTypeObjectTypeField:
		queryVal, ok := q.Value.(string)
		if ok {
			assetTypeFields.ObjectType = ObjectType(queryVal)
		}
	case assetTypeClassField:
		queryVal, ok := q.Value.(string)
		if ok {
			assetTypeFields.Class = queryVal
		}
	case assetTypeCategoryField:
		queryVal, ok := q.Value.(string)
		if ok {
			assetTypeFields.Category = queryVal
		}
	case assetTypeFamilyField:
		queryVal, ok := q.Value.(string)
		if ok {
			assetTypeFields.Family = queryVal
		}
	case assetTypeGroupField:
		queryVal, ok := q.Value.(string)
		if ok {
			assetTypeFields.Group = queryVal
		}
	case assetTypeOrderField:
		queryVal, ok := q.Value.(string)
		if ok {
			assetTypeFields.Order = queryVal
		}
	case assetTypeKindField:
		queryVal, ok := q.Value.(string)
		if ok {
			assetTypeFields.Kind = queryVal
		}
	}

	return assetTypeFields
}

func interfaceToArrayOfInterfaces(v interface{}) ([]interface{}, bool) {
	switch v := v.(type) {
	case []interface{}:
		return v, true
	case primitive.A:
		return v, true
	default:
		return []interface{}{}, false
	}
}
