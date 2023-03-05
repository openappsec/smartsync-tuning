package redis

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rueian/rueidis"
	"openappsec.io/errors"
)

var (
	// textSearchTokenizationSeparators is a map from all characters that need to be prefixed with "\\"
	// to their corresponding prefixed string
	textSearchTokenizationSeparators = map[string]string{
		",": "\\,", ".": "\\.", "<": "\\<", ">": "\\>", "{": "\\{", "}": "\\}", "[": "\\[",
		"]": "\\]", "\"": "\\\"", "'": "\\'", ":": "\\:", ";": "\\;", "!": "\\!", "@": "\\@",
		"#": "\\#", "$": "\\$", "%": "\\%", "^": "\\^", "&": "\\&", "*": "\\*",
		"(": "\\(", "-": "\\-", "+": "\\+", "=": "\\=", "~": "\\~",
	}
)

// StackAdapter represents a redis stack adapter
// this adapter supports the main redis stack modules: "regular" redis, redis json and redis search
type StackAdapter[T any] struct {
	Adapter
}

// NewStackClient return a new redis stack adapter
func NewStackClient[T any]() *StackAdapter[T] {
	return &StackAdapter[T]{}
}

// ReplaceTokenizationSeparators excepts a string and prepends a double-backslash (\\) to
// all of the following characters:
// ",", ".", "<", ">", "{", "}", "[", "]", "\"", "'", ":", ";", "!", "@", "#", "$", "%", "^", "&", "*", "(", "-", "+", "=", "~"
// this is done to allow a string that contains one of those characters to be searchable
// see redisearch tokenization documentation here: https://redis.io/docs/stack/search/reference/escaping/
// exceptions is a sublist of the above characters which the function will not replace
func ReplaceTokenizationSeparators(toReplace string, exceptions ...string) string {
	ret := toReplace
	for tokenizationSeparator, prefixedTokenizationSeparator := range textSearchTokenizationSeparators {
		skip := false
		for _, exception := range exceptions {
			if tokenizationSeparator == exception {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		ret = strings.ReplaceAll(ret, tokenizationSeparator, prefixedTokenizationSeparator)
	}

	return ret
}

// redisResultToStruct converts the result from redis to the desired type
// first, the function extract the value as string and then unmarshal it to the desired type
func redisResultToStruct[T any](redisResult rueidis.RedisMessage) (T, error) {
	var ret T
	resString, err := redisResult.ToString()
	if err != nil {
		if errStr := fmt.Sprintf("%s", err); strings.Contains(errStr, "redis nil message") {
			return ret, errors.Wrapf(err, "Redis result is empty").SetClass(errors.ClassNotFound)
		}

		return ret, errors.Wrapf(err, "Failed to extract value as string from redis result")
	}

	// this is to revert the ReplaceTokenizationSeparators operation
	resString = strings.ReplaceAll(resString, "\\", "")

	if unmarshalErr := json.Unmarshal([]byte(resString), &ret); unmarshalErr != nil {
		return ret, errors.Wrapf(unmarshalErr, "Failed to unmarshal value as string to desired type")

	}

	return ret, nil
}

// projectionRedisResultToStruct converts the result from Redis to a projection of a document
func projectionRedisResultToStruct[T any](redisResult rueidis.RedisMessage) (T, error) {
	var ret T
	redisResultStringMap, toStringMapErr := redisResult.AsStrMap()
	if toStringMapErr != nil {
		return ret, errors.Wrapf(toStringMapErr, "Failed to convert projection to map")
	}

	toMarshal := make(map[string]any)
	for k, v := range redisResultStringMap {
		k = strings.ReplaceAll(k, "\\", "")
		v = strings.ReplaceAll(v, "\\", "")
		splitAttributeName := strings.Split(k, attributePathSeparator)
		// non nested field
		if len(splitAttributeName) == 1 {
			toMarshal[k] = v
			continue
		}

		// nested field
		splitWithValue := append(splitAttributeName, v)
		toMarshal[splitWithValue[0]] = sliceToNestedMap(splitWithValue[1:])
	}

	mapBytes, marshalErr := json.Marshal(toMarshal)
	if marshalErr != nil {
		return ret, errors.Wrapf(marshalErr, "Failed to marshal Redis result as nested map (%#v)", toMarshal)
	}

	if err := json.Unmarshal(mapBytes, &ret); err != nil {
		return ret, errors.Wrapf(marshalErr,
			"Failed to unmarshal Redis result as nested map (%#v) to desired struct type (%#v)", toMarshal, ret)
	}

	return ret, nil
}

// sliceToNestedMap is used to handle a search command with projection
// it converts a nested field to a nested map to be converted to the desired type
func sliceToNestedMap(in []string) map[string]any {
	if len(in) == 2 {
		return map[string]any{
			in[0]: in[1],
		}
	}

	ret := make(map[string]any)
	ret[in[0]] = sliceToNestedMap(in[1:])
	return ret
}
