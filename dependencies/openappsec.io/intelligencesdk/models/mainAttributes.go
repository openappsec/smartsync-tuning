package models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"openappsec.io/errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	// String representation of the possible types of the values of MainAttributes once applying reflect.TypeOf()
	typeStringArray    = "[]string"
	typeString         = "string"
	typeInterfaceArray = "[]interface {}"

	// String representation fo MONGO SPECIFIC type primitive.A (type A []interface{}) once applying reflect.TypeOf()
	typePrimitiveA = "primitive.A"

	// String representation for generic type interface{}
	typeInterface = "interface{}"
)

// MainAttributes defines an assets. They can be either map[string]string, map[string][]string or map[string]interface{} in which values are only string or []string
type MainAttributes map[string]interface{}

// MainAttributesList represents list of MainAttributes
type MainAttributesList []MainAttributes

// Match returns true if the given MainAttributesList matches the given MainAttributesList
func (mal MainAttributesList) Match(other MainAttributesList) bool {
	if len(mal) != len(other) {
		return false
	}

	for i := range mal {
		if !mal[i].Match(other[i]) {
			return false
		}
	}

	return true
}

// Match returns true if the given MainAttributes matches the given MainAttributes
func (ma MainAttributes) Match(other MainAttributes) bool {
	if len(ma) != len(other) {
		return false
	}

	sortedMainAttributes, err := ma.Sort()
	if err != nil {
		return false
	}

	sortedOtherMainAttributes, err := ma.Sort()
	if err != nil {
		return false
	}

	marshalledSortedMainAttributes, err := sortedMainAttributes.MarshalJSON()
	if err != nil {
		return false
	}

	marshalledSortedOtherMainAttributes, err := sortedOtherMainAttributes.MarshalJSON()
	if err != nil {
		return false
	}

	return bytes.Equal(marshalledSortedMainAttributes, marshalledSortedOtherMainAttributes)
}

// Copy creates a copy of the MainAttributes
func (ma MainAttributes) Copy() (MainAttributes, error) {
	copyVal := func(val interface{}) (interface{}, error) {
		valType := fmt.Sprintf("%s", reflect.TypeOf(val))
		switch valType {
		case typeString:
			return val, nil
		case typeStringArray:
			valArr, ok := val.([]string)
			if !ok {
				return "", errors.Errorf("Failed to convert value %+v into string array", val)
			}
			valCpy := make([]string, len(valArr))
			reflect.Copy(reflect.ValueOf(valCpy), reflect.ValueOf(valArr))
			return valCpy, nil
		case typeInterfaceArray:
			valArr, err := interfaceToStringArray(val)
			if err != nil {
				return "", errors.Wrapf(err, "Failed to convert value %+v into string array", val)
			}
			valCpy := make([]string, len(valArr))
			reflect.Copy(reflect.ValueOf(valCpy), reflect.ValueOf(valArr))
			return valCpy, nil
		default:
			return "", errors.Errorf("Expected value to be string or []string but got: %s. Value is: %+v", valType, val)
		}
	}

	res := make(MainAttributes, len(ma))
	for key, val := range ma {
		cpyVal, err := copyVal(val)
		if err != nil {
			return MainAttributes{}, errors.Wrap(err, "Failed to copy MainAttributes")
		}
		res[key] = cpyVal
	}

	return res, nil
}

// Validate checks each value in MainAttributes is either of typeString or of typeStringArray
// It fails if type is primitive.A since this type is only expected to be received from Mongo
// and Validate is called on input from request body (handler)
func (ma MainAttributes) Validate() error {
	// Since MainAttributes isn't of type interface, can't do type assertion.
	// Need to transverse over all key-value pairs and make sure values are either of type string or []string
	for key, val := range ma {
		valType := fmt.Sprintf("%s", reflect.TypeOf(val))
		switch valType {
		case typeString, typeStringArray:
			continue
		case typeInterfaceArray:
			_, err := interfaceToStringArray(val)
			if err != nil {
				return errors.Wrapf(err, "Failed to convert mainAttributes.%s to %s", key, typeStringArray)
			}
		default:
			return errors.Errorf("Expected MainAttributes of type %s, %s or %s, got type %s for mainAttributes.%s", typeString, typeStringArray, typeInterfaceArray, valType, key)
		}
	}

	return nil
}

// MarshalJSON implements the json.Marshaler interface. It instructs how to Marshal MainAttributes :
// It first calls MainAttributes.Sort and then calls json.Marshal
// It would result in an error in case:
//  1. MainAttributes.Sort failed
//  2. json.Marshal failed
func (ma MainAttributes) MarshalJSON() ([]byte, error) {
	sortedMainAtt, err := ma.Sort()
	if err != nil {
		return []byte{}, err
	}

	// Cast to map[string]interface{} to avoid recursive call to MarshalJson
	mapToMarshal := map[string]interface{}(sortedMainAtt)
	return json.Marshal(mapToMarshal)
}

// Sort returns a copy of the MainAttributes in which all values which are of type []string are sorted
// It would result in an error in case:
//  1. The value is not of typeString, typeStringArray or typeInterfaceArray (and can be converted to this types)
//  2. The value is of typeInterfaceArray and can not be converted into typeStringArray
//
// ------------------------------------------------------------------------------------------------------------
// NOTICE: typePrimitiveA is *** MONGO SPECIFIC *** type - ([]interface{}). Since we need to marshal
// MainAttributes of Assets returned from Mongo --> typePrimitiveA was added as a special case.
// ------------------------------------------------------------------------------------------------------------
func (ma MainAttributes) Sort() (MainAttributes, error) {
	sortedMainAttributes := make(map[string]interface{}, len(ma))

	// Iterate over key-value pairs and update mainAttToMarshal. In case the value is typeStringArray - sort it.
	for key, val := range ma {
		valType := fmt.Sprintf("%s", reflect.TypeOf(val))
		switch valType {
		case typeStringArray:
			valArr, ok := val.([]string)
			if !ok {
				return MainAttributes{}, errors.Errorf("Failed to convert value %+v into %s)", val, typeStringArray)
			}
			sort.Strings(valArr)
			sortedMainAttributes[key] = valArr
		case typeString:
			valStr, ok := val.(string)
			if !ok {
				return MainAttributes{}, errors.Errorf("Failed to assert value %+v into %s)", val, typeString)
			}
			sortedMainAttributes[key] = valStr
		case typeInterfaceArray:
			valStringArr, err := interfaceToStringArray(val)
			if err != nil {
				return MainAttributes{}, errors.Wrapf(err, "Failed to convert value %+v into %s", val, typeStringArray)
			}
			sort.Strings(valStringArr)
			sortedMainAttributes[key] = valStringArr
		case typePrimitiveA:
			valPrimitive, ok := val.(primitive.A)
			if !ok {
				return MainAttributes{}, errors.Errorf("Failed to assert value %+v as %s)", val, typePrimitiveA)
			}
			valInterfaceArr := []interface{}(valPrimitive)
			valStringArr, err := interfaceToStringArray(valInterfaceArr)
			if err != nil {
				return MainAttributes{}, errors.Wrapf(err, "Failed to convert value %+v into %s", val, typeStringArray)
			}
			sort.Strings(valStringArr)
			sortedMainAttributes[key] = valStringArr
		default:
			return MainAttributes{}, errors.Errorf("Expected MainAttributes of type %s, %s, %s or %s, got type %s for mainAttributes.%s", typeString, typeStringArray, typeInterfaceArray, typePrimitiveA, valType, key)
		}
	}

	return sortedMainAttributes, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// After unmarshaling, if the values of MainAttributes are:
//  1. Only strings
//     --> reflect.TypeOf(val) would result in typeString
//  2. Only []string
//     -->  reflect.TypeOf(val) would result in typeStringArray
//  3. Mix of strings and []string
//     --> if val is string 	--> reflect.TypeOf(val) would result in typeString
//     -->	if val is []string	--> reflect.TypeOf(val) would result in typeInterfaceArray
func (ma *MainAttributes) UnmarshalJSON(b []byte) error {
	// Make sure the map was initialized before unmarshal
	if *ma == nil {
		*ma = make(MainAttributes)
	}
	return ma.unmarshal(b)
}

func (ma MainAttributes) unmarshal(b []byte) error {
	possibleMainAttTypes := []string{typeString, typeStringArray, typeInterface}

	for _, possibleType := range possibleMainAttTypes {
		switch possibleType {
		case typeString:
			mainAtt := make(map[string]string)
			err := json.Unmarshal(b, &mainAtt)
			if err == nil {
				for key, val := range mainAtt {
					ma[key] = val
				}
				return nil
			}
		case typeStringArray:
			mainAtt := make(map[string][]string)
			err := json.Unmarshal(b, &mainAtt)
			if err == nil {
				for key, val := range mainAtt {
					ma[key] = val
				}
				return nil
			}
		case typeInterface:
			mainAtt := make(map[string]interface{})
			err := json.Unmarshal(b, &mainAtt)
			if err == nil {
				for key, val := range mainAtt {
					ma[key] = val
				}
				return nil
			}
		default:
			return errors.Errorf("Failed to unmarshal mainAttributes")
		}
	}
	return errors.Errorf("Failed to unmarshal mainAttributes")
}

func interfaceToStringArray(val interface{}) ([]string, error) {
	interfaceArray, ok := val.([]interface{})
	if !ok {
		return []string{}, errors.Errorf("Failed to convert value %+v into %s", val, typeInterfaceArray)
	}

	var stringArr []string
	for _, interVal := range interfaceArray {
		strVal, ok := interVal.(string)
		if !ok {
			return []string{}, errors.Errorf("Failed to convert value %+v into string", strVal)
		}
		stringArr = append(stringArr, strVal)
	}

	return stringArr, nil
}
