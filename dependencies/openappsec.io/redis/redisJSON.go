package redis

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/opentracing/opentracing-go"
	"github.com/rueian/rueidis"
	"github.com/rueian/rueidis/om"
	"openappsec.io/errors"
	"openappsec.io/log"
	"openappsec.io/tracer"
)

// NXorXXOption defines the nx/xx flags of json.set commands as enum
type NXorXXOption string

const (
	// NX allows the set operation only if the key dos not exist
	NX NXorXXOption = "onlyIfNotExists"

	// XX allows the set operation only if the key already exist
	XX NXorXXOption = "onlyIfExists"
)

func (option NXorXXOption) toString() string {
	var ret string
	switch option {
	case NX:
		ret = "only if key does not exist"
	case XX:
		ret = "only if key exists"
	default:
		ret = "set key in any case"
	}

	return ret
}

// SetJSONOptions defines the json.set command
// options which includes:
// 1. NX (set only if key does not exist) or XX (set only if key already exist) flags (default is to set in any case)
// 2. Update a specific field specified by path
type SetJSONOptions struct {
	NXorXXOption NXorXXOption
	Path         string
}

// SetJSONRecord is used to pass a key of a json record, a path inside the json record and the value to be set
type SetJSONRecord struct {
	Key     string
	Value   any
	Options *SetJSONOptions
}

// SetJSONRecords is a slice of SetJSONRecord - used to pass multiple keys and values to be set
type SetJSONRecords []SetJSONRecord

// DeleteJSONOptions defines the json.del command options which includes:
// 1. Deleting a specific path inside the json record
type DeleteJSONOptions struct {
	Path string
}

// DeleteJSONRecord is used to pass a key of a json record and the path inside that record to be deleted
// if path is empty then deletes the whole record
type DeleteJSONRecord struct {
	Key  string
	Path string
}

// DeleteJSONRecords is a slice of DeleteJSONRecord - used to pass multiple keys and their respective paths to be deleted
type DeleteJSONRecords []DeleteJSONRecord

// GetJSONOptions defines the json.get command options which includes:
// 1. Projection should be a list of fields where nested fields should be specified by dot notation.
// for example:
// if we have a record under "key": {"a": "hi", "b": {"c": "hey"}}
// and we call get with {Key: "key", Projection: []string{"b.c"}}
// then we will get back {"b": {"c": "hey"}}
type GetJSONOptions struct {
	Projection []string
}

// GetJSONRecord is used to pass a key of a json record and a projection of that record to be retrieved
// if projection is empty then retrieves the whole record
// Projection should be a list of fields where nested fields should be specified by dot notation.
// for example:
// if we have a record under "key": {"a": "hi", "b": {"c": "hey"}}
// and we call get with {Key: "key", Projection: []string{"b.c"}}
// then we will get back {"b": {"c": "hey"}}
type GetJSONRecord struct {
	Key        string
	Projection []string
}

// GetJSONRecords is a slice of GetJSONRecord - used to pass multiple keys and paths to be retrieved from Redis
type GetJSONRecords []GetJSONRecord

// BulkError is used to wrap the error return from a bulk operation with the index
// of the failed operation
type BulkError struct {
	Error error
	Index int
}

// BulkErrors is a slice of BulkError objects
type BulkErrors []BulkError

// parseJSONValue is used to replace all tokenization separators in string attributes
// we use a recursive function here to handle nested string attributes
func parseJSONValue(toParse any) (any, error) {
	switch toParse.(type) {
	case string:
		return ReplaceTokenizationSeparators(toParse.(string)), nil
	case []any:
		valueAnySlice := toParse.([]any)
		retSlice := make([]any, len(valueAnySlice))
		for index, anyMember := range valueAnySlice {
			parsedMember, err := parseJSONValue(anyMember)
			if err != nil {
				return toParse, err
			}

			retSlice[index] = parsedMember
		}

		return retSlice, nil
	case map[string]any:
		retMap := make(map[string]any, len(toParse.(map[string]any)))
		for k, v := range toParse.(map[string]any) {
			parsedVal, err := parseJSONValue(v)
			if err != nil {
				return toParse, err
			}

			retMap[k] = parsedVal
		}

		return retMap, nil
	}

	toParseBytes, err := json.Marshal(toParse)
	if err != nil {
		return toParse, errors.Wrapf(err, "Failed to marshal value during parsing").SetClass(errors.ClassInternal)
	}

	var mapToParse map[string]any
	if unmarshalErr := json.Unmarshal(toParseBytes, &mapToParse); unmarshalErr != nil {
		// this means that the value is not a struct which is possible, hence ignore the error
		// and just return the value as is
		return toParse, nil
	}

	return parseJSONValue(mapToParse)
}

// SetJSON sets the given input json value to the given Key
// if Path != nil then sets the value to the nested Key defined in Path
func (a *StackAdapter[T]) SetJSON(ctx context.Context, key string, value any, opts ...*SetJSONOptions) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetJSON")

	var nxOrXX NXorXXOption
	if len(opts) != 0 {
		if len(opts) > 1 {
			return errors.Errorf("Too many 'SetJSONOptions' arguments passed to function").
				SetClass(errors.ClassBadInput)
		}

		nxOrXX = opts[0].NXorXXOption
	}

	value, err := parseJSONValue(value)
	if err != nil {
		return errors.Wrapf(err, "Failed to parse JSON value")
	}

	command := a.createJSONSetCommand(key, value, opts...)
	if res := a.stackClient.Do(ctx, command); res.Error() != nil {
		return errors.Wrapf(res.Error(), "Failed to run command json.set with option (%s)", nxOrXX.toString()).
			SetClass(errors.ClassInternal)
	}

	return nil
}

// SetAllBulkJSON sets the given values under the given keys under the specified path and NX or XX options
// This function should be used if one wants to set multiple values with the same options (path and NX/XX)
// If path option is empty - all values should be valid JSON records
// If NXOrXXOption is empty - the value will be set either if the key exists or not
// note that options inside the jsonRecords arguments are ignored
func (a *StackAdapter[T]) SetAllBulkJSON(ctx context.Context, jsonRecords SetJSONRecords, opts ...*SetJSONOptions) BulkErrors {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetAllBulkJSON")

	var options *SetJSONOptions
	if len(opts) > 0 {
		if len(opts) > 1 {
			return BulkErrors{
				{
					Error: errors.Errorf("Too many 'SetJSONOptions' arguments passed to function").
						SetClass(errors.ClassBadInput),
				},
			}
		}

		options = opts[0]
	}

	setRecords := make(SetJSONRecords, len(jsonRecords))
	for i, record := range jsonRecords {
		record.Options = options
		setRecords[i] = record
	}

	return a.SetSpecificBulkJSON(ctx, setRecords)
}

// SetSpecificBulkJSON sets all given values to their respectful keys and paths
// this function should be used only if one wants to set multiple values with different options
// if all options are the same - use SetAllBulkJSON
func (a *StackAdapter[T]) SetSpecificBulkJSON(ctx context.Context, jsonRecords SetJSONRecords) BulkErrors {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetSpecificBulkJSON")

	cmds := make(rueidis.Commands, len(jsonRecords))
	for i, jsonRecord := range jsonRecords {
		parsedValue, parsingErr := parseJSONValue(jsonRecord.Value)
		if parsingErr != nil {
			log.WithContext(ctx).WithEventID("c6628ab2-f478-41e6-8bd5-68403a744627").
				Errorf("Failed to parse JSON value at index (%d)", i)
			continue
		}
		var cmdToAdd om.Completed
		if jsonRecord.Options != nil {
			cmdToAdd = a.createJSONSetCommand(jsonRecord.Key, parsedValue, jsonRecord.Options)
		} else {
			cmdToAdd = a.createJSONSetCommand(jsonRecord.Key, parsedValue)
		}

		cmds[i] = cmdToAdd
	}

	var errs BulkErrors
	for i, resp := range a.stackClient.DoMulti(ctx, cmds...) {
		if err := resp.Error(); err != nil {
			errs = append(errs, BulkError{
				Error: errors.Wrapf(err, "Failed to run command json.set (If error is nil, check NX/XX flags)").
					SetClass(errors.ClassInternal),
				Index: i,
			})
		}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

// GetJSON gets the json value saved under the given key
// opts defines the projection options of the json.get command which includes
// defining a projection of the json record to retrieve
// for example if the record is:
//
//	myKey := {
//		key1: "val1",
//		key2: "val2",
//		key3: {
//			key4: "val3",
//		}
//	}
//
// and we call GetJSON(ctx, &GetJSONOptions{Projection: []string{"myKey", "key1", "key3.key4"}}) we will get:
//
//	{
//			key1: "val1",
//			key3: {
//				key4: "val3"
//			}
//	}
//
// if no projection is given - retrieves the whole record
func (a *StackAdapter[T]) GetJSON(ctx context.Context, key string, opts ...*GetJSONOptions) (T, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "GetJSON")

	if len(opts) > 1 {
		var empty T
		return empty, errors.Errorf("Too many 'GetJSONOptions' arguments passed to function").
			SetClass(errors.ClassBadInput)
	}

	var command om.Completed
	if len(opts) > 0 {
		command = a.createJSONGetCommand(key, opts[0].Projection...)
	} else {
		command = a.createJSONGetCommand(key)
	}

	res := a.stackClient.Do(ctx, command)
	resMessage, _ := res.ToMessage()
	return redisResultToStruct[T](resMessage)
}

// GetAllBulkJSON gets all JSON records under the given keys with the specified projection in opts
// This function should be used if one wants to get the same projection from all keys
// If opts is empty - retrieves the whole record
func (a *StackAdapter[T]) GetAllBulkJSON(ctx context.Context, keys []string, opts ...*GetJSONOptions) ([]T, BulkErrors) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "GetAllBulkJSON")

	var projection []string
	if len(opts) > 0 {
		if len(opts) > 1 {
			return nil, BulkErrors{
				{
					Error: errors.Errorf("Too many 'GetJSONOptions' arguments passed to function").
						SetClass(errors.ClassBadInput),
				},
			}
		}

		projection = opts[0].Projection
	}

	getRecords := make(GetJSONRecords, len(keys))
	for i, key := range keys {
		getRecords[i] = GetJSONRecord{Key: key, Projection: projection}
	}

	return a.GetSpecificBulkJSON(ctx, getRecords)
}

// GetSpecificBulkJSON gets all JSON records according to the given keys and projections
// this function should be used only if one wants to get different fields from different records
// otherwise - use GetAllBulkJSON
func (a *StackAdapter[T]) GetSpecificBulkJSON(ctx context.Context, getRecords GetJSONRecords) ([]T, BulkErrors) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "GetSpecificBulkJSON")

	cmds := make(rueidis.Commands, len(getRecords))
	for i, getRecord := range getRecords {
		cmdToAdd := a.createJSONGetCommand(getRecord.Key, getRecord.Projection...)
		cmds[i] = cmdToAdd
	}

	var errs BulkErrors
	ret := make([]T, 0, len(getRecords))
	for i, resp := range a.stackClient.DoMulti(ctx, cmds...) {
		if err := resp.Error(); err != nil {
			errs = append(errs, BulkError{
				Error: err,
				Index: i,
			})
			continue
		}

		respMessage, _ := resp.ToMessage()
		toAdd, err := redisResultToStruct[T](respMessage)
		if err != nil {
			errs = append(errs, BulkError{
				Error: errors.Wrapf(err, "Failed to convert result to desired type").
					SetClass(errors.ClassInternal),
				Index: i,
			})
			continue
		}

		ret = append(ret, toAdd)
	}

	if len(errs) > 0 {
		return ret, errs
	}

	return ret, nil
}

// DeleteJSON deletes from the given key the values specified by paths
// if path is nil then deletes the whole record
func (a *StackAdapter[T]) DeleteJSON(ctx context.Context, key string, opts ...*DeleteJSONOptions) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "DeleteJSON")

	var path string
	if len(opts) != 0 {
		if len(opts) > 1 {
			return errors.Errorf("Too many 'DeleteJSONOptions' arguments passed to function").
				SetClass(errors.ClassBadInput)
		}

		path = opts[0].Path
	}

	cmd := a.createJSONDelCommand(key, path)
	res := a.stackClient.Do(ctx, cmd)
	if res.Error() != nil {
		return errors.Wrapf(res.Error(), "Failed to run command json.del").SetClass(errors.ClassInternal)
	}

	resInt, _ := res.AsInt64()
	if resInt == 0 {
		return errors.Errorf("Key (%s) and path (%s) to delete not found", key, path).SetClass(errors.ClassNotFound)
	}

	return nil
}

// DeleteAllBulkJSON deletes the given path in all given keys
// This function should be used if one wants to make the same change in all keys
func (a *StackAdapter[T]) DeleteAllBulkJSON(ctx context.Context, keys []string, opts ...*DeleteJSONOptions) BulkErrors {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "DeleteAllBulkJSON")

	var path string
	if len(opts) != 0 {
		if len(opts) > 1 {
			return BulkErrors{
				{
					Error: errors.Errorf("Too many 'DeleteJSONOptions' arguments passed to function").SetClass(errors.ClassBadInput),
				},
			}
		}

		path = opts[0].Path
	}

	deleteRecords := make(DeleteJSONRecords, len(keys))
	for i, key := range keys {
		deleteRecords[i] = DeleteJSONRecord{Key: key, Path: path}
	}

	return a.DeleteSpecificBulkJSON(ctx, deleteRecords)
}

// DeleteSpecificBulkJSON deletes from each key the given path
// this function should be used only if one wants to delete different fields in different records
// otherwise - use DeleteAllBulkJSON
func (a *StackAdapter[T]) DeleteSpecificBulkJSON(ctx context.Context, jsonRecords DeleteJSONRecords) BulkErrors {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "DeleteSpecificBulkJSON")

	cmds := make(rueidis.Commands, len(jsonRecords))
	for i, jsonRecord := range jsonRecords {
		cmdToAdd := a.createJSONDelCommand(jsonRecord.Key, jsonRecord.Path)
		cmds[i] = cmdToAdd
	}

	var errs BulkErrors
	for i, resp := range a.stackClient.DoMulti(ctx, cmds...) {
		if err := resp.Error(); err != nil {
			errs = append(errs, BulkError{
				Error: err,
				Index: i,
			})
		}

		respInt, _ := resp.AsInt64()
		if respInt == 0 {
			errs = append(errs, BulkError{
				Error: errors.Errorf("Key (%s) and path (%s) to delete  not found", jsonRecords[i].Key, jsonRecords[i].Path).
					SetClass(errors.ClassNotFound),
				Index: i,
			})
		}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

// createJSONGetCommand creates a json.get command to be executed
// the function adds to the path the "$." prefix if necessary
// and adds the index keys prefix to the key
func (a *StackAdapter[T]) createJSONGetCommand(key string, paths ...string) om.Completed {
	fullPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		fullPaths = append(fullPaths, fmt.Sprintf("$.%s", path))
	}

	return a.stackClient.B().JsonGet().Key(key).Paths(fullPaths...).Build()
}

// createJSONSetCommand creates a json.set command to be executed
// the function adds to the path the "$." prefix if necessary
// and adds the index keys prefix to the key
func (a *StackAdapter[T]) createJSONSetCommand(key string, value any, opts ...*SetJSONOptions) om.Completed {
	fullPath := "$"
	var nxOrXX NXorXXOption
	if len(opts) != 0 {
		nxOrXX = opts[0].NXorXXOption
		if opts[0].Path != "" {
			fullPath = fmt.Sprintf("$.%s", opts[0].Path)
		}
	}

	var ret om.Completed
	switch nxOrXX {
	case NX:
		// only if key does not exist
		ret = a.stackClient.B().JsonSet().Key(key).Path(fullPath).Value(rueidis.JSON(value)).Nx().Build()
	case XX:
		// only if key exist
		ret = a.stackClient.B().JsonSet().Key(key).Path(fullPath).Value(rueidis.JSON(value)).Xx().Build()
	default:
		// default is to allow both cases
		ret = a.stackClient.B().JsonSet().Key(key).Path(fullPath).Value(rueidis.JSON(value)).Build()
	}

	return ret
}

// createJSONDelCommand creates a json.del command to be executed
// the function adds to the given path the "$." prefix if necessary
// and adds the index keys prefix to the key
func (a *StackAdapter[T]) createJSONDelCommand(key string, path string) om.Completed {
	fullPath := "$"
	if path != "" {
		fullPath = fmt.Sprintf("$.%s", path)
	}

	return a.stackClient.B().JsonDel().Key(key).Path(fullPath).Build()
}
