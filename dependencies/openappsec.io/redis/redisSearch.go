package redis

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/opentracing/opentracing-go"
	"github.com/rueian/rueidis"
	"github.com/rueian/rueidis/om"
	"openappsec.io/errors"
	"openappsec.io/log"
	"openappsec.io/tracer"
)

// SchemaFieldType defines a redis search schema type as enum
type SchemaFieldType string

const (
	// SchemaTextType is used to define a redis search schema field of type text (string)
	SchemaTextType SchemaFieldType = "text"

	// SchemaNumericType is used to define a redis search schema field of type numeric (int, int64, float, etc..)
	SchemaNumericType SchemaFieldType = "numeric"

	// SchemaTagType is used to define a redis search schema field of type tag
	SchemaTagType SchemaFieldType = "tag"

	// SchemaVectorType is used to define a redis search schema field of type vector
	SchemaVectorType SchemaFieldType = "vector"

	// SchemaGeoType is used to define a redis search schema field of type geo
	SchemaGeoType SchemaFieldType = "geo"
)

const (
	// defaultOffset defines the default offset of a sorted paging search query
	// the offset is zero which means the result page will start with the first document
	defaultOffset int64 = 0

	// defaultLimit defines the default size of a page of a sorted paging search query
	defaultLimit int64 = 20
)

// PagingCursor defines a cursor for the next page to retrieve
type PagingCursor struct {
	Offset int64
	Limit  int64
}

// SearchOptions represents all search options
type SearchOptions struct {
	// InFields will apply the query only on the given fields - all fields need to be indexed as well
	// if no InFields is given, then the query will be applied on all indexed fields
	InFields []string

	// Projection defines a projection of the documents that will be returned from the search query
	Projection []string

	// SortBy will sort the search query result by the given value
	SortBy string

	// Descending will return a sorted response in descending order.
	// Should be used only if the SortBy option is not empty
	// default is Ascending
	Descending bool

	// Paging defines a cursor for retrieving the next page of a search query result
	// Should be used with SortBy option to insure order between queries
	Paging *PagingCursor

	// onlyKeys - if true the result will not contain documents, but will contain the list
	// of keys associated with the result documents
	// This option is not exported, use KeysSearch or KeysSearchComplexQuery functions instead
	onlyKeys bool

	// count - if true will return the number of documents that match the given search query
	// This option is not exported, use CountSearch and CountSearchComplexQuery instead
	count bool
}

// NumericOperand represents a numeric range query operand
type NumericOperand struct {
	// Field should be an indexed field
	// nested field should be referenced with dot notation
	Field string

	// Min represent the lower boundaries of a range query on numeric value
	Min string

	// ExcludeMin - if true, then the lower boundary itself will not be included in the range query
	ExcludeMin bool

	// Max represent the upper boundaries of a range query on numeric value
	Max string

	// ExcludeMax - if true, then the upper boundary itself will not be included in the range query
	ExcludeMax bool
}

func (operand *NumericOperand) toStringQuery() string {
	if operand.Min == "" {
		operand.Min = minInfinityRange
	} else if operand.ExcludeMin {
		operand.Min = fmt.Sprintf("%s%s", exclusiveBoundary, operand.Min)
	}

	if operand.Max == "" {
		operand.Max = maxInfinityRange
	} else if operand.ExcludeMax {
		operand.Max = fmt.Sprintf("%s%s", exclusiveBoundary, operand.Max)
	}

	return fmt.Sprintf("(@%s:[%s %s])", ConvertFieldPathToAttributeName(operand.Field), operand.Min, operand.Max)
}

// NumericOperands represents a slice of NumericOperand
type NumericOperands []NumericOperand

func (operands NumericOperands) toStringQuery(operator Operator) string {
	if len(operands) == 1 {
		return operands[0].toStringQuery()
	}

	queryStringSlice := make([]string, len(operands))
	for index, operand := range operands {
		queryStringSlice[index] = operand.toStringQuery()
	}

	return fmt.Sprintf("(%s)", strings.Join(queryStringSlice, string(operator)))
}

const (
	// minInfinityRange represents (-infinity) which is used as a lower boundary
	// for numeric range queries when no lower boundary is given by the user
	minInfinityRange = "-inf"

	// maxInfinityRange represents (+infinity) which is used as an upper boundary
	// for numeric range queries when no upper boundary is given by the user
	maxInfinityRange = "inf"

	// exclusiveBoundary - if added as a prefix to a range query boundary then the boundary
	// itself will not be included in the range
	exclusiveBoundary = "("
)

// TextOperand Represents a text operand in a search query
type TextOperand struct {
	// Field should be an indexed field
	// nested field should be referenced with dot notation
	Field string

	// TextOperands value can include the following operators (remember to set Regex to true if operators are used):
	// * - any prefix or suffix (note that this cannot be used between letters. For example: so*e is an invalid query)
	// | - or operator
	// & - and operator
	// "-" - not operator
	// () - parentheses (for operators order of execution)
	// "<some expression>" - quotes for exact expression
	Value string

	// Regex if true then will treat operators characters as operators
	// otherwise, they will be treated as "normal" characters
	// possible operators:
	// * - any prefix or suffix (note that this cannot be used between letters. For example: so*e is an invalid query)
	// | - or operator
	// & - and operator
	// "-" - not operator
	// () - parentheses (for operators order of execution)
	// "<some expression>" - quotes for exact expression
	Regex bool
}

const (
	// SearchAllValuesQuery is the query to pass to the Search functions in order to search for all documents
	SearchAllValuesQuery = "*"
)

var (
	textOperandValuePossibleOperators = []string{"*", "|", "&", "-", "(", ")", "\"", "'"}
)

// TextOperands represents a slice of TextOperand
type TextOperands []TextOperand

func (operand *TextOperand) toStringQuery() string {
	if operand.Regex {
		return fmt.Sprintf("@%s:%s", ConvertFieldPathToAttributeName(operand.Field),
			ReplaceTokenizationSeparators(operand.Value, textOperandValuePossibleOperators...))
	}

	return fmt.Sprintf("@%s:%s", ConvertFieldPathToAttributeName(operand.Field),
		ReplaceTokenizationSeparators(operand.Value))
}

func (operands TextOperands) toStringQuery(operator Operator) string {
	if len(operands) == 1 {
		return operands[0].toStringQuery()
	}

	queryStringSlice := make([]string, len(operands))
	for index, operand := range operands {
		queryStringSlice[index] = operand.toStringQuery()
	}

	return fmt.Sprintf("(%s)", strings.Join(queryStringSlice, string(operator)))
}

// TagOperand searches are used for ENUM like values
// TagOperands searches are used for ENUM like values
type TagOperand struct {
	// Field should be an indexed field
	// nested field should be referenced with dot notation
	Field string

	// Value is a string slice containing possible ENUM like values
	Value []string
}

// TagOperands represents a slice of TagOperand
type TagOperands []TagOperand

func (operand *TagOperand) toStringQuery() string {
	return fmt.Sprintf("(@%s:{%s})", ConvertFieldPathToAttributeName(operand.Field),
		strings.Join(operand.Value, string(Or)))
}

func (operands TagOperands) toStringQuery(operator Operator) string {
	if len(operands) == 1 {
		return operands[0].toStringQuery()
	}

	queryStringSlice := make([]string, len(operands))
	for index, operand := range operands {
		queryStringSlice[index] = operand.toStringQuery()
	}

	return fmt.Sprintf("(%s)", strings.Join(queryStringSlice, string(operator)))
}

// Operator represent a search query operator
type Operator string

const (
	// And represents an "AND" operator in a query
	And Operator = "&"

	// Or represents an "OR" operator in a query
	Or Operator = "|"

	// Not represents an "NOT" operator in a query
	Not Operator = "-"
)

// SearchQuery defines a complex search query for types text, numeric and tag
// follows the query syntax documentation -https://redis.io/docs/stack/search/reference/query_syntax/
// Important note about "NOT" operator: if more than one operand is given, than the "NOT" operator will be applied on
// each operand and an "AND" operator will be added between those negations
type SearchQuery struct {
	Operator                    Operator        `json:"operator,omitempty"`
	OperandsWithNestedOperators []SearchQuery   `json:"operandsWithNestedOperators,omitempty"`
	TextOperands                TextOperands    `json:"textOperands,omitempty"`
	NumericOperands             NumericOperands `json:"numericOperands,omitempty"`
	TagOperands                 TagOperands     `json:"tagOperands,omitempty"`
}

const (
	userFieldPathSeparator = "."
	attributePathSeparator = "_"
)

// AggregationReduceFunc defines a name of a reduce function to use with aggregation GroupBy option
type AggregationReduceFunc string

const (
	// count is the "COUNT" aggregation function
	// will return a map where:
	// key = a value of the requested property
	// value = the number of documents which contains the value under the given property
	count AggregationReduceFunc = "COUNT"

	// min is the "MIN" aggregation function which returns
	// the minimal value if the requested property (text values are considered as zero)
	min AggregationReduceFunc = "MIN"

	// max is the "MAX" aggregation function which returns
	// the maximal value if the requested property (text values are considered as zero)
	max AggregationReduceFunc = "MAX"

	// sum is the "SUM" aggregation function which returns
	// the sum of all values of a given property (text values are considered as zero)
	sum AggregationReduceFunc = "SUM"

	// average if the "AVERAGE" aggregation function which returns
	// the average of all values of a given property (text values are considered as zero)
	average AggregationReduceFunc = "Average"

	// toList is the "TOLIST" aggregation function which returns
	// a slice of all distinct values of a given property
	toList AggregationReduceFunc = "TOLIST"
)

func (reducer AggregationReduceFunc) string() string {
	return string(reducer)
}

// FacetsResponseValueAndCount represents an entry in a facet query response
// which is a value of the requested attribute and the number of documents which includes
// that value under the requested attribute
type FacetsResponseValueAndCount struct {
	Value string
	Count int64
}

// FacetsResponse represent a single facet query response
// Res is a map from a value of a requested attribute to the number of documents which includes that value under the requested attribute
type FacetsResponse struct {
	Res   map[string]int
	Error error
}

// ConvertFieldPathToAttributeName converts a field path (nested fields are represented with dot notation)
// to attribute name by replace all dots with underscore
// In addition, removes [*] which is used to represent a field containing a list of json like objects
// this is done to simplify the attributes names
func ConvertFieldPathToAttributeName(fieldPath string) string {
	fieldPathNoList := strings.ReplaceAll(fieldPath, "[*]", "")
	return strings.ReplaceAll(fieldPathNoList, userFieldPathSeparator, attributePathSeparator)
}

// CreateIndex creates the redis search index sets the search schema for it.
// searchSchema is a map from a Key name to its type. A type can only be one of: "text", "number", "tag", "vector", "geo".
// Note that the schema fields should match existing fields in the given struct type T
// where nested fields should be named with dot notation ("a.b" represents the field of a struct {a: {b: <some-value>}}).
// Each nested field will be saved in schema with underscore ("_") instead of dot ("."),
// for example: the field "a.b" can be also searched as "a_b"
func (a *StackAdapter[T]) CreateIndex(ctx context.Context, searchSchema map[string]SchemaFieldType, indexName, prefix string) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "CreateIndex")

	var invalidSchemaFieldsErrors []error
	var createIndexCommand om.FtCreateSchema
	var finalCommand om.Completed
	createIndexCommand = a.stackClient.B().FtCreate().Index(indexName).OnJson().Prefix(1).Prefix(prefix).
		Stopwords(0).Schema()
	// fieldsCounter is used in order to know when to actually build the command
	fieldsCounter, schemaSize := 0, len(searchSchema)
	for k, v := range searchSchema {
		fieldsCounter++
		buildAndBreak := fieldsCounter == schemaSize
		name := fmt.Sprintf("$.%s", k)
		nameNoDots := ConvertFieldPathToAttributeName(k)
		switch v {
		case SchemaTextType:
			if buildAndBreak {
				finalCommand = createIndexCommand.FieldName(name).As(nameNoDots).Text().Sortable().Unf().Build()
				break
			}
			createIndexCommand = om.FtCreateSchema(createIndexCommand.FieldName(name).As(nameNoDots).Text().Sortable().Unf())
		case SchemaNumericType:
			if buildAndBreak {
				finalCommand = createIndexCommand.FieldName(name).As(nameNoDots).Numeric().Sortable().Build()
				break
			}
			createIndexCommand = om.FtCreateSchema(createIndexCommand.FieldName(name).As(nameNoDots).Numeric().Sortable())
		case SchemaTagType:
			if buildAndBreak {
				finalCommand = createIndexCommand.FieldName(name).As(nameNoDots).Tag().Build()
				break
			}
			createIndexCommand = om.FtCreateSchema(createIndexCommand.FieldName(name).As(nameNoDots).Tag())
		case SchemaVectorType:
			if buildAndBreak {
				finalCommand = createIndexCommand.FieldName(name).As(nameNoDots).Vector().Build()
				break
			}
			createIndexCommand = om.FtCreateSchema(createIndexCommand.FieldName(name).As(nameNoDots).Vector())
		case SchemaGeoType:
			if buildAndBreak {
				finalCommand = createIndexCommand.FieldName(name).As(nameNoDots).Geo().Build()
				break
			}
			createIndexCommand = om.FtCreateSchema(createIndexCommand.FieldName(name).As(nameNoDots).Geo())
		default:
			invalidSchemaFieldsErrors = append(invalidSchemaFieldsErrors,
				errors.Errorf("Got invalid schema type: %s for field: %s. Please choose one of: [%s, %s, %s, %s, %s]",
					v, k, SchemaTextType, SchemaNumericType, SchemaTagType, SchemaVectorType, SchemaGeoType))
		}
	}

	if len(invalidSchemaFieldsErrors) > 0 {
		return errors.Errorf("Got invalid schema field. Errors: %+v", invalidSchemaFieldsErrors).
			SetClass(errors.ClassBadInput)
	}

	if res := a.stackClient.Do(ctx, finalCommand); res.Error() != nil {
		// index does not exist
		if strings.Contains(res.Error().Error(), "Index already exists") {
			log.WithContext(ctx).WithEventID("0c188d10-9929-438d-92d9-88cbb73a8521").
				Warnf("Log from Redis package: index (%s) already exists", indexName)
			return nil
		}

		return errors.Wrapf(res.Error(), "Failed to run command ft.create (create index) command").
			SetClass(errors.ClassInternal)
	}

	return nil
}

// DropIndex drops (deletes) the index of the redis search client
// if index doesn't exist the function will not return an error and will just output a warning log
func (a *StackAdapter[T]) DropIndex(ctx context.Context, indexName string) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "DropIndex")

	dropIndexCommand := a.stackClient.B().FtDropindex().Index(indexName).Build()
	if res := a.stackClient.Do(ctx, dropIndexCommand); res.Error() != nil {
		// index does not exist
		if strings.Contains(res.Error().Error(), "Unknown Index name") {
			log.WithContext(ctx).WithEventID("6f9d84a6-ea29-419f-bb64-5ff764f602c2").
				Warnf("Log from Redis package: index (%s) does not exist, no index was dropped", indexName)
			return nil
		}

		return errors.Wrapf(res.Error(), "Failed to drop index (%s)", indexName).SetClass(errors.ClassInternal)
	}

	return nil
}

// ListIndexes runs the "ft._list" command and returns a slice containing all indexes names
func (a *StackAdapter[T]) ListIndexes(ctx context.Context) ([]string, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "ListIndexes")

	listIndexesCommand := a.stackClient.B().FtList().Build()
	res := a.stackClient.Do(ctx, listIndexesCommand)
	indexesList, err := res.AsStrSlice()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to convert ft._list command result to string array")
	}

	return indexesList, nil
}

// ToStringQuery converts the filter to a valid Redisearch string query
// according to the query syntax defined here - https://redis.io/docs/stack/search/reference/query_syntax/
// If no operator is given, default operator will be "And"
func (query *SearchQuery) ToStringQuery() string {
	if query.Operator == "" {
		query.Operator = And
	}

	var stringQueries []string

	// complex query
	if len(query.OperandsWithNestedOperators) > 0 {
		operandsAsString := make([]string, len(query.OperandsWithNestedOperators))
		for index, complexOperand := range query.OperandsWithNestedOperators {
			operandsAsString[index] = complexOperand.ToStringQuery()
		}

		stringQueries = append(stringQueries, fmt.Sprintf("(%s)", strings.Join(operandsAsString, string(query.Operator))))
	}

	if len(query.TextOperands) > 0 {
		stringQueries = append(stringQueries, query.TextOperands.toStringQuery(query.Operator))
	}

	if len(query.NumericOperands) > 0 {
		stringQueries = append(stringQueries, query.NumericOperands.toStringQuery(query.Operator))
	}

	if len(query.TagOperands) > 0 {
		stringQueries = append(stringQueries, query.TagOperands.toStringQuery(query.Operator))
	}

	// if "Not" operator is given with multiple operands
	// the result is and "And" operator between the negation of all operands
	if query.Operator == Not {
		return fmt.Sprintf("(-%s)", strings.Join(stringQueries, fmt.Sprintf("%s%s", string(And), string(Not))))
	}

	return fmt.Sprintf("(%s)", strings.Join(stringQueries, string(query.Operator)))
}

// CountSearchComplexQuery returns the number of records that match the given query
func (a *StackAdapter[T]) CountSearchComplexQuery(ctx context.Context, indexName string, searchQuery SearchQuery) (int64, error) {
	return a.CountSearch(ctx, indexName, searchQuery.ToStringQuery())
}

// CountSearch returns the number of records which match the given query
// this function should be for simple text search
// otherwise use CountSearchComplexQuery which has a much more friendly interface
// if you still want to specify a complex query yourself, please follow the documentation
// here: https://redis.io/docs/stack/search/reference/query_syntax/
func (a *StackAdapter[T]) CountSearch(ctx context.Context, indexName, queryString string) (int64, error) {
	command := a.createSearchCommand(indexName, queryString, &SearchOptions{count: true})
	res := a.stackClient.Do(ctx, command)
	if res.Error() != nil {
		return 0, errors.Wrapf(res.Error(), "Failed to get number of records which match the search query (%s)",
			queryString).SetClass(errors.ClassInternal)
	}

	resInt, err := res.AsIntSlice()
	if err != nil {
		return 0, errors.Wrapf(err, "Failed to convert result from redis to int64. Response from redis: %+v",
			res).SetClass(errors.ClassInternal)
	}

	return resInt[0], nil
}

// KeysSearchComplexQuery returns the keys of the records that match the given filter
func (a *StackAdapter[T]) KeysSearchComplexQuery(ctx context.Context, indexName string, searchQuery SearchQuery) ([]string, error) {
	return a.KeysSearch(ctx, indexName, searchQuery.ToStringQuery())
}

// KeysSearch returns the keys of the records which that the given query
// this function should be for simple text search
// otherwise use KeysSearchComplexQuery which has a much more friendly interface
// if you still want to specify a complex query yourself, please follow the documentation
// here: https://redis.io/docs/stack/search/reference/query_syntax/
func (a *StackAdapter[T]) KeysSearch(ctx context.Context, indexName, queryString string) ([]string, error) {
	command := a.createSearchCommand(indexName, queryString, &SearchOptions{onlyKeys: true})
	res := a.stackClient.Do(ctx, command)
	if res.Error() != nil {
		return nil, errors.Wrapf(res.Error(), "Failed to get keys of records which match the search query (%s)",
			queryString).SetClass(errors.ClassInternal)
	}

	resStringArray, err := res.AsStrSlice()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to convert result from redis to string slice. Response from redis: %+v",
			res).SetClass(errors.ClassInternal)
	}

	return resStringArray[1:], nil
}

// SearchComplexQuery executes a search query defined by a searchQuery and options
// Do not use this function with the "InFields" search option
// If no operator is given, the default operator will be "And"
func (a *StackAdapter[T]) SearchComplexQuery(ctx context.Context, indexName string, searchQuery SearchQuery, opts ...*SearchOptions) ([]T, error) {
	return a.SearchSimpleQuery(ctx, indexName, searchQuery.ToStringQuery(), opts...)
}

// SearchSimpleQuery executes a search query defined by a query and options
// this function should be for simple text search
// otherwise use SearchComplexQuery which has a much more friendly interface
// if you still want to specify a complex query yourself, please follow the documentation
// here: https://redis.io/docs/stack/search/reference/query_syntax/
// if you want to search for all documents in index please pass as query the following: "*" (this package has this
// value exported as SearchAllValuesQuery)
// if you run texts searches directly from this function and not with SearchComplexQuery please make sure to read about
// Tokenization here - https://redis.io/docs/stack/search/reference/escaping/
// For text search please apply the ReplaceTokenizationSeparators on the text value to search
func (a *StackAdapter[T]) SearchSimpleQuery(ctx context.Context, indexName, queryString string, opts ...*SearchOptions) ([]T, error) {
	var checkOpts SearchOptions
	if len(opts) > 0 {
		checkOpts = *opts[0]
	}

	if len(opts) > 1 {
		return nil, errors.Errorf("Too many 'SearchOptions' arguments passed to function").SetClass(errors.ClassBadInput)
	}

	searchCommand := a.createSearchCommand(indexName, queryString, opts...)
	res := a.stackClient.Do(ctx, searchCommand)
	if res.Error() != nil {
		return nil, errors.Wrapf(res.Error(), "Failed to run ft.search searchCommand. Query: %s. Options: %+v",
			queryString, checkOpts).SetClass(errors.ClassInternal)
	}

	resSlice, err := res.ToArray()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to convert result from Redisearch to results slice. Response from Redis: %+v",
			res).SetClass(errors.ClassInternal)
	}

	// the returned slice is built in the following way:
	// first element is the number of records found
	// after that, all elements can be divided into ordered pairs where:
	// first element is the key
	// second element is an array in which the last element contains the wanted value
	// hence we will iterate (in chunks of size 2) over the result from the third element
	var ret []T
	for index := 2; index < len(resSlice); index += 2 {
		var toAdd T
		var toAddErr error
		currVal := resSlice[index]
		if len(checkOpts.Projection) > 0 {
			toAdd, toAddErr = projectionRedisResultToStruct[T](currVal)
		} else {
			valueArray, _ := currVal.ToArray()
			toAdd, toAddErr = redisResultToStruct[T](valueArray[len(valueArray)-1])
		}

		if toAddErr != nil {
			// key is locates in the final element of the slice
			key, _ := resSlice[index-1].ToString()
			var empty T
			log.WithContext(ctx).WithEventID("c260000e-ac21-43cd-b424-08862c1cd145").
				Errorf("Log from Redis package: Failed to parse search result of key (%s) to desired type (%#v). Error: %s",
					key, empty, toAddErr)
			continue
		}

		ret = append(ret, toAdd)
	}

	return ret, nil
}

// createSearchCommand creates a ft.search  command according to the given parameters
func (a *StackAdapter[T]) createSearchCommand(indexName, queryString string, opts ...*SearchOptions) om.Completed {
	searchCommand := a.stackClient.B().FtSearch().Index(indexName).Query(queryString)
	if len(opts) > 0 {
		// if "only keys" flag is on then return only keys
		if opts[0].onlyKeys {
			return searchCommand.Nocontent().Build()
		}

		offset := defaultOffset
		limit := defaultLimit
		withLimit := false
		if opts[0].Paging != nil {
			withLimit = true
			offset = opts[0].Paging.Offset
			limit = opts[0].Paging.Limit
		}

		// if "count" flag is on - than just return the number of records which match the query
		// this is done by setting both offset and limit to zero
		if opts[0].count {
			withLimit = true
			offset = 0
			limit = 0
		}

		// if InFields is an empty slice Redisearch will just ignore it
		searchInFieldsCommand := searchCommand.Infields(fmt.Sprintf("%d", len(opts[0].InFields))).Field(opts[0].InFields...)

		projectionAttributes := make([]string, len(opts[0].Projection))
		for index, projectionField := range opts[0].Projection {
			projectionAttributes[index] = ConvertFieldPathToAttributeName(projectionField)
		}

		isSort := opts[0].SortBy != ""
		isDescending := isSort && opts[0].Descending
		isProjection := len(opts[0].Projection) > 0
		isAscending := !isDescending && isSort

		switch true {
		// sort descending and projection
		case isDescending && isProjection:
			searchWithProjection := searchInFieldsCommand.Return(fmt.Sprintf("%d", len(projectionAttributes))).Identifier(projectionAttributes[0])
			for _, identifier := range projectionAttributes[1:] {
				searchWithProjection = searchWithProjection.Identifier(identifier)
			}

			if withLimit {
				return searchWithProjection.
					Sortby(ConvertFieldPathToAttributeName(opts[0].SortBy)).Desc().Limit().OffsetNum(offset, limit).Build()
			}

			return searchWithProjection.
				Sortby(ConvertFieldPathToAttributeName(opts[0].SortBy)).Desc().Build()

		// sort ascending and projection
		case isAscending && isProjection:
			searchWithProjection := searchInFieldsCommand.Return(fmt.Sprintf("%d", len(projectionAttributes))).Identifier(projectionAttributes[0])
			for _, identifier := range projectionAttributes[1:] {
				searchWithProjection = searchWithProjection.Identifier(identifier)
			}

			if withLimit {
				return searchWithProjection.
					Sortby(ConvertFieldPathToAttributeName(opts[0].SortBy)).Asc().Limit().OffsetNum(offset, limit).Build()
			}

			return searchWithProjection.
				Sortby(ConvertFieldPathToAttributeName(opts[0].SortBy)).Asc().Build()

		// sort descending
		case isDescending && !isProjection:
			if withLimit {
				return searchInFieldsCommand.
					Sortby(ConvertFieldPathToAttributeName(opts[0].SortBy)).Desc().Limit().OffsetNum(offset, limit).Build()
			}

			return searchInFieldsCommand.
				Sortby(ConvertFieldPathToAttributeName(opts[0].SortBy)).Desc().Build()

		// sort ascending
		case isAscending && !isProjection:
			if withLimit {
				return searchInFieldsCommand.
					Sortby(ConvertFieldPathToAttributeName(opts[0].SortBy)).Asc().Limit().OffsetNum(offset, limit).Build()
			}

			return searchInFieldsCommand.
				Sortby(ConvertFieldPathToAttributeName(opts[0].SortBy)).Asc().Build()

		// only projection not sorted
		case !isSort && isProjection:
			searchWithProjection := searchInFieldsCommand.Return(fmt.Sprintf("%d", len(projectionAttributes))).Identifier(projectionAttributes[0])
			for _, identifier := range projectionAttributes[1:] {
				searchWithProjection = searchWithProjection.Identifier(identifier)
			}

			if withLimit {
				return searchWithProjection.Limit().OffsetNum(offset, limit).Build()
			}

			return searchWithProjection.Build()

		// default - no sort nor projection - only paging
		default:
			if withLimit {
				return searchCommand.Limit().OffsetNum(offset, limit).Build()
			}

			return searchCommand.Build()
		}
	}

	return searchCommand.Build()
}

// FacetsOptions defines the possible options for a facets query
type FacetsOptions struct {
	// BucketMaxSize defines the max size of the bucket of each requested property
	// the bucket will contain the BucketMaxSize top options
	BucketMaxSize int
}

// FacetsComplexQuery parses the search query and performs a facet operation as described in FacetsSimpleQuery documentation
func (a *StackAdapter[T]) FacetsComplexQuery(ctx context.Context, indexName string, searchQuery SearchQuery,
	propertiesNames []string, opts ...*FacetsOptions) (map[string]FacetsResponse, error) {
	return a.FacetsSimpleQuery(ctx, indexName, searchQuery.ToStringQuery(), propertiesNames, opts...)
}

// FacetsSimpleQuery executes a pipeline of aggregation commands (command for each propertyName) with a "COUNT" reducer which counts
// the number of occurrences of each possible value for a given property
// This function returns a map from the property name to its facet operation result
// for example if we run Facets(ctx, "someIndex", SearchAllValuesQuery, "name", "age") the result will be:
//
//	{
//			"name": {
//					"name1": <the number of documents which has the property "name" with value "name1">,
//					...
//					"name-n": <the number of documents which has the property "name" with value "name1">,
//					},
//			"age": {
//					"1": <the number of documents which has the property "age" with value "1">,
//					...
//					"m": <the number of documents which has the property "age" with value "m">,
//					},
//	}
func (a *StackAdapter[T]) FacetsSimpleQuery(ctx context.Context, indexName, queryString string,
	propertiesNames []string, opts ...*FacetsOptions) (map[string]FacetsResponse, error) {
	maxBucketSize := 0
	if len(opts) > 0 {
		if len(opts) > 1 {
			return nil, errors.Errorf("Too many 'FacetsOptions' arguments passed to function").SetClass(errors.ClassBadInput)
		}

		maxBucketSize = opts[0].BucketMaxSize
	}

	commands := make(rueidis.Commands, len(propertiesNames))
	indexToPropertyNameMap := make(map[int]string, len(propertiesNames))
	for index, property := range propertiesNames {
		command := a.stackClient.B().FtAggregate().Index(indexName).Query(queryString).
			Groupby(1).Property(fmt.Sprintf("@%s", ConvertFieldPathToAttributeName(property))).
			Reduce(count.string()).Nargs(0)
		if maxBucketSize > 0 {
			commands[index] = command.As("redisCount").Sortby(2).Property("@redisCount").Desc().
				Max(int64(maxBucketSize)).Build()
		} else {
			commands[index] = command.Build()
		}

		indexToPropertyNameMap[index] = property
	}

	ret := make(map[string]FacetsResponse, len(propertiesNames))
	for i, resp := range a.stackClient.DoMulti(ctx, commands...) {
		propertyName := indexToPropertyNameMap[i]
		if resp.Error() != nil {
			ret[propertyName] = FacetsResponse{
				Error: errors.Wrapf(resp.Error(), "Failed to calculate facets for property (%s). Query: %s. Index: %s",
					propertyName, queryString, indexName),
			}
			continue
		}

		// if no error occurred than the response is a slice of Redis messages
		// the first element is the length of the slice (starting from the second element)
		// each element in the slice (starting from the second element) is a slice as well where:
		// the second element is the value of the property and the last element is the count
		valSlice, err := resp.ToArray()
		if err != nil {
			ret[propertyName] = FacetsResponse{
				Error: errors.Wrapf(err, "Failed to convert facets result to array for property (%s)",
					propertyName),
			}
			continue
		}

		// iterating from second member because the first is the length of the
		// entire response and has no meaning to us
		propertyFacetsRes := make(map[string]int)
		for _, valMember := range valSlice[1:] {
			valMemberSlice, _ := valMember.ToArray()
			propertyValue, _ := valMemberSlice[1].ToString()
			if propertyValue == "" {
				continue
			}

			propertyValue = strings.ReplaceAll(propertyValue, "\\", "")
			propertyValueCountString, _ := valMemberSlice[len(valMemberSlice)-1].ToString()
			propertyValueCount, _ := strconv.Atoi(propertyValueCountString)
			propertyFacetsRes[propertyValue] = propertyValueCount
		}

		ret[propertyName] = FacetsResponse{
			Res: propertyFacetsRes,
		}
	}

	return ret, nil
}
