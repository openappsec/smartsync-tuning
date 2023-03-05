package models

import (
	"encoding/json"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"openappsec.io/errors"
)

// DataRequestField represents the data requested fields
type DataRequestField string

// DataRequest represents the data requested
type DataRequest []RequestedAttribute

// known data requests
const (
	DataReqCountryCode              DataRequestField = FieldAttributes + ".countryCode"
	DataReqCountryName              DataRequestField = FieldAttributes + ".countryName"
	DataReqASN                      DataRequestField = FieldAttributes + ".asn"
	DataReqReputationClassification DataRequestField = FieldAttributes + ".reputationClassification"
	DataReqReputationSeverity       DataRequestField = FieldAttributes + ".reputationSeverity"
	DataReqReputationConfidence     DataRequestField = FieldAttributes + ".reputationConfidence"

	// DataReqMalwareTypes used by threatcloud-aux
	DataReqMalwareTypes DataRequestField = FieldAttributes + ".malwareTypes"
)

// FindDataRequestInAsset accepts a data request field and returns its value in the given asset, nil if it is not part of the asset
func (a *Asset) FindDataRequestInAsset(drf DataRequestField) (interface{}, error) {
	assBytes, err := json.Marshal(a)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to marshal asset")
	}
	assParsed, err := gabs.ParseJSON(assBytes)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load asset into gabs")
	}
	res := assParsed.Path(string(drf)).Data()
	if res == nil {
		return nil, errors.Errorf("Asset does not contain field (%s)", drf).SetClass(errors.ClassNotFound)
	}
	return res, nil
}

// AddDataRequestToAsset inserts a DataRequestField into the acted upon asset
// TODO return even if DataRequestField doesn't start with attribute
func (a *Asset) AddDataRequestToAsset(drf DataRequestField, val interface{}) error {
	kys := strings.Split(string(drf), ".")
	switch k := kys[0]; k {
	case FieldAttributes:
		attrs, err := dotNotationToMap(kys[1:], val)
		if err != nil {
			return errors.Wrapf(err, "Invalid requested attribute field specified (%s)", drf)
		}
		for attrKey, attrVal := range attrs {
			a.Attributes[attrKey] = attrVal
		}
	default:
		return errors.New("Invalid requested attribute specified")
	}
	return nil
}

func dotNotationToMap(kys []string, val interface{}) (map[string]interface{}, error) {
	if len(kys) < 1 {
		return nil, errors.New("Empty split array specified")
	}
	if len(kys) < 2 {
		return map[string]interface{}{
			kys[0]: val,
		}, nil
	}
	v, err := dotNotationToMap(kys[1:], val)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		kys[0]: v,
	}, nil
}
