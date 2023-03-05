package models

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

// InvalidationType represents the invalidation types: add, update, delete
type InvalidationType string

// InvalidationTypeAdd Supported invalidation types
const (
	InvalidationTypeAdd InvalidationType = "add"
)

// InvalidationData contains the data we perform assets invalidation by
type InvalidationData struct {
	Class          string             `json:"class"`
	Category       string             `json:"category,omitempty"`
	Family         string             `json:"family,omitempty"`
	Group          string             `json:"group,omitempty"`
	Order          string             `json:"order,omitempty"`
	Kind           string             `json:"kind,omitempty"`
	MainAttributes MainAttributesList `json:"mainAttributes,omitempty"`
	ObjectType     ObjectType         `json:"objectType,omitempty"`
	SourceID       string             `json:"sourceId,omitempty"`
	// TenantID is only sent to source who registered for invalidations made by all tenants
	TenantID         string           `json:"tenantId,omitempty"`
	InvalidationType InvalidationType `json:"invalidationType,omitempty"`
}

// InvalidationsData is a list of InvalidationData
type InvalidationsData []InvalidationData

// ReportedInvalidations is the invalidations sent by the client for an intelligence assets invalidations
type ReportedInvalidations struct {
	InvalidationsData InvalidationsData `json:"invalidations,omitempty"`
}

// AsyncInvalidations is the invalidations sent by async child to the cloud
type AsyncInvalidations struct {
	ReportedInvalidations
	SourceID string `json:"sourceId,omitempty"`
	TenantID string `json:"tenantId,omitempty"`
}

// CrossTenantQueryInvalidationData is a struct to hold a query that was invalidated and the ID of the tenant who made that query.
type CrossTenantQueryInvalidationData struct {
	QueryID              string       `json:"queryId,omitempty"`
	Query                IntelQueryV2 `json:"query"`
	QueryTenantID        string       `json:"queryTenantId"`
	InvalidationTenantID string       `json:"invalidationTenantId"`
}

// CrossTenantQueryInvalidationRegistration is the cross tenant query invalidation registration data
type CrossTenantQueryInvalidationRegistration struct {
	Name              string                           `json:"name"`
	TenantID          string                           `json:"tenantId"`
	SourceID          string                           `json:"sourceId"`
	URL               string                           `json:"url"`
	APIVersion        string                           `json:"apiVersion"`
	CommunicationType CommunicationType                `json:"communicationType"`
	InvalidationData  CrossTenantQueryInvalidationData `json:"invalidationData"`
}

// InvalidationReg is the invalidation registration request sent by each source
type InvalidationReg struct {
	Name                string              `json:"name,omitempty"`
	URL                 string              `json:"url"`
	APIVersion          string              `json:"apiVersion,omitempty"`
	CommunicationType   CommunicationType   `json:"communicationType,omitempty"`
	DataMap             InvalidationsData   `json:"dataMap,omitempty"`
	CrossTenantDataMaps CrossTenantDataMaps `json:"crossTenantDataMaps,omitempty"`
	CrossTenantQueries  *CrossTenantQueries `json:"crossTenantQueries,omitempty"`
	TenantID            string              `json:"tenantId,omitempty"` // Not from request body, added to struct before saving to cache
	SourceID            string              `json:"sourceId,omitempty"` // Not from request body, added to struct before saving to cache
}

// CreateUniqueInvalidationsData takes an InvalidationsData object and returns a new InvalidationsData object with no duplicates
func CreateUniqueInvalidationsData(in InvalidationsData) InvalidationsData {
	var uniqueInvalidations InvalidationsData
	uniqueInvalidationsMap := make(map[string]InvalidationData)
	for _, invalidation := range in {
		invalidationStr := fmt.Sprintf("%+v", invalidation)
		if _, ok := uniqueInvalidationsMap[invalidationStr]; !ok {
			uniqueInvalidationsMap[invalidationStr] = invalidation
			uniqueInvalidations = append(uniqueInvalidations, invalidation)
		}
	}

	return uniqueInvalidations
}

// AddObjectType adds the default object type to each invalidation data if its empty
func (in *InvalidationsData) AddObjectType() {
	for i := range *in {
		(*in)[i].AddObjectType()
	}
}

// AddObjectType adds the default object type to the invalidation data if its empty
func (in *InvalidationData) AddObjectType() {
	if in.ObjectType == MissingObjectType {
		in.ObjectType = DefaultObjectType
	}
}

// Match returns true if the invalidation data matches the given invalidation data
func (in *InvalidationData) Match(matcher InvalidationData) bool {
	if in.Class != matcher.Class ||
		in.Category != matcher.Category ||
		in.Family != matcher.Family ||
		in.Group != matcher.Group ||
		in.Order != matcher.Order ||
		in.Kind != matcher.Kind ||
		in.ObjectType != matcher.ObjectType {
		return false
	}

	if !in.MainAttributes.Match(matcher.MainAttributes) {
		return false
	}

	return true
}

// MatchInvalidationToRegistration checks if the invalidation received matches the invalidation registration. If it does, returns all the matching parts in the invalidation registration dataMap
func (ir *InvalidationReg) MatchInvalidationToRegistration(invalidation InvalidationData) (InvalidationRegSrcDataList, error) {
	res := InvalidationRegSrcDataList{}

	// This function is used while comparing the registration to the invalidation.
	// It returns true in case there's a verdict and the comparison process can stop, otherwise false.
	// A verdict is reached if:
	// (1) The assetType field isn't in the registration request --> found match
	// (2) The assetType field is in the registration request BUT not in the invalidation --> found match
	// (3) The assetType field is in both the registration and the invalidation but with different values. --> found mismatch
	// In cases 1 & 2 | --> also need to update the final result
	reachedVerdictAfterComparingAssetTypes := func(regInval InvalidationData, assetTypeFieldInvalReg, assetTypeFieldInval string) bool {
		if assetTypeFieldInvalReg == "" || (assetTypeFieldInvalReg != "" && assetTypeFieldInval == "") {
			res = append(res, ir.CreateInvalidationRegSrcData(Identity{TenantID: ir.TenantID, SourceID: ir.SourceID}, regInval))
			return true
		}

		if assetTypeFieldInvalReg != assetTypeFieldInval {
			return true
		}

		return false
	}

	// This function checks if any of the mainAttributes listed in the registration appears in invalidation
	// Returns true in case there's a match to at least one of the mainAttributes in the invalidation.
	// Returns false in case of an error or if no match was found
	checkForMainAttMatch := func(regInvalMainAtt MainAttributesList) (bool, error) {
		regInvalMainAttMap := make(map[string]struct{})
		for _, mainAtt := range regInvalMainAtt {
			mainAttBytes, err := json.Marshal(mainAtt)
			if err != nil {
				return false, errors.Wrap(err, "Failed to marshal mainAttributes of invalidation registration")
			}

			regInvalMainAttMap[string(mainAttBytes)] = struct{}{}
		}

		for _, mainAtt := range invalidation.MainAttributes {
			mainAttBytes, err := json.Marshal(mainAtt)
			if err != nil {
				return false, errors.Wrap(err, "Failed to marshal mainAttributes of received invalidation")
			}

			if _, ok := regInvalMainAttMap[string(mainAttBytes)]; ok {
				return true, nil
			}
		}

		return false, nil
	}

	match := func(regInval InvalidationData) error {
		if reachedVerdictAfterComparingAssetTypes(regInval, string(regInval.ObjectType), string(invalidation.ObjectType)) {
			return nil
		}

		if reachedVerdictAfterComparingAssetTypes(regInval, regInval.Class, invalidation.Class) {
			return nil
		}

		if reachedVerdictAfterComparingAssetTypes(regInval, regInval.Category, invalidation.Category) {
			return nil
		}

		if reachedVerdictAfterComparingAssetTypes(regInval, regInval.Family, invalidation.Family) {
			return nil
		}

		compareGroupOrderKind := func() {
			if reachedVerdictAfterComparingAssetTypes(regInval, regInval.Group, invalidation.Group) {
				return
			}

			if reachedVerdictAfterComparingAssetTypes(regInval, regInval.Order, invalidation.Order) {
				return
			}

			reachedVerdictAfterComparingAssetTypes(regInval, regInval.Kind, invalidation.Kind)
		}

		// If there are no mainAttributes in the registration request OR there are mainAttributes in the registration request BUT not in the invalidation -> need to compare only group, order, and kind.
		if len(regInval.MainAttributes) == 0 || (len(regInval.MainAttributes) != 0 && len(invalidation.MainAttributes) == 0) {
			compareGroupOrderKind()
			return nil
		}

		foundMatch, err := checkForMainAttMatch(regInval.MainAttributes)
		if err != nil {
			return err
		}

		// If didn't found a match in the mainAttributes -> move to the next registration.
		if !foundMatch {
			return nil
		}

		compareGroupOrderKind()

		return nil
	}

	for _, regInval := range ir.DataMap {
		if err := match(regInval); err != nil {
			return InvalidationRegSrcDataList{}, err
		}
	}

	for _, regInval := range ir.CrossTenantDataMaps {
		if err := match(regInval.InvalidationMatcher); err != nil {
			return InvalidationRegSrcDataList{}, err
		}
	}

	return res, nil
}

// MatchCrossTenantQueriesInvalidationToRegistration checks if the cross tenant query invalidation received matches the invalidation registration.
// If it does, returns the matching query in the invalidation registration as it was originally registered with.
func (ir *InvalidationReg) MatchCrossTenantQueriesInvalidationToRegistration(ctx context.Context, queryInvalidation CrossTenantQueryInvalidationData) (CrossTenantQueryInvalidationRegistration, error) {
	for i := range ir.CrossTenantQueries.Queries {
		if ir.CrossTenantQueries.Queries[i].ID(ctx) == queryInvalidation.QueryID {
			return CrossTenantQueryInvalidationRegistration{
				Name:              ir.Name,
				TenantID:          ir.TenantID,
				SourceID:          ir.SourceID,
				URL:               ir.URL,
				APIVersion:        ir.APIVersion,
				CommunicationType: ir.CommunicationType,
				InvalidationData: CrossTenantQueryInvalidationData{
					QueryID:              queryInvalidation.QueryID,
					Query:                ir.CrossTenantQueries.OriginalQueries[i],
					QueryTenantID:        queryInvalidation.QueryTenantID,
					InvalidationTenantID: queryInvalidation.InvalidationTenantID,
				},
			}, nil
		}
	}

	return CrossTenantQueryInvalidationRegistration{}, nil
}
