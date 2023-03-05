package models

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"openappsec.io/errors"
	"openappsec.io/log"
)

// AssetSource is the unique part of each asset.
type AssetSource struct {
	TenantID       string                 `json:"tenantId" bson:"tenantId"`
	SourceID       string                 `json:"sourceId" bson:"sourceId"`
	AgentID        string                 `json:"agentId,omitempty" bson:"agentId,omitempty"`
	AssetID        string                 `json:"assetId,omitempty" bson:"assetId,omitempty"`
	TTL            int                    `json:"ttl" bson:"ttl"`
	ExpirationTime *time.Time             `json:"expirationTime,omitempty" bson:"expirationTime,omitempty"`
	Tags           map[string]string      `json:"tags,omitempty" bson:"tags,omitempty"`
	Confidence     int                    `json:"confidence" bson:"confidence"`
	Attributes     map[string]interface{} `json:"attributes,omitempty" bson:"attributes,omitempty"`
}

// AssetsSource is a list of AssetSource
type AssetsSource []AssetSource

// AssetCollection is a representation of a group of assets with common features (such as mainAttributes and name)
// The common features are all the features listed in the AssetCollection root.
// All the assets which belong to this collection (stripped form the common features (AssetSource)) are placed in a list ("Sources")
type AssetCollection struct {
	SchemaVersion          int            `json:"schemaVersion" bson:"schemaVersion"`
	AssetType              string         `json:"assetType" bson:"assetType"`
	AssetTypeSchemaVersion int            `json:"assetTypeSchemaVersion" bson:"assetTypeSchemaVersion"`
	PermissionType         string         `json:"permissionType" bson:"permissionType"`
	PermissionGroupID      string         `json:"permissionGroupId,omitempty" bson:"permissionGroupId,omitempty"`
	Name                   string         `json:"name" bson:"name"`
	ObjectType             ObjectType     `json:"objectType" bson:"objectType"`
	Class                  string         `json:"class" bson:"class"`
	Category               string         `json:"category" bson:"category"`
	Family                 string         `json:"family" bson:"family"`
	Group                  string         `json:"group,omitempty" bson:"group,omitempty"`
	Order                  string         `json:"order,omitempty" bson:"order,omitempty"`
	Kind                   string         `json:"kind,omitempty" bson:"kind,omitempty"`
	MainAttributes         MainAttributes `json:"mainAttributes" bson:"mainAttributes"`
	Sources                AssetsSource   `json:"sources,omitempty" bson:"sources,omitempty"`
}

// AssetCollections is a list of AssetCollection
type AssetCollections []AssetCollection

// calcCollectionID calculates the collectionID for the asset.
// A collectionID is sha256 over the concatenation of the unique fields of the collection
func (a Asset) calcCollectionID(ctx context.Context) (string, error) {
	// Step 1: Use the assetID instead of mainAttributes and all the asset type fields
	id, _, err := a.GetAssetID(ctx)
	if err != nil {
		return "", errors.Wrap(err, "Failed to get the asset ID")
	}

	// Step 2: Concat the unique fields of the asset collection (which do not take part in asset ID calculation)
	concatUniqueFields := []byte(fmt.Sprintf("%s%d%s%d%s%s%s%s", id, a.SchemaVersion, a.AssetType, a.AssetTypeSchemaVersion, a.PermissionType, a.PermissionGroupID, a.Name, a.Version))
	sum := sha256.Sum256(concatUniqueFields)
	// sum is an array of 32 bytes --> turn it into a slice before encoding (used syntax [:])
	return hex.EncodeToString(sum[:]), nil
}

// CalcAssetID calculates the assetID for the collection.
func (a AssetCollection) CalcAssetID() (string, error) {
	assetForID := Asset{
		ObjectType:     a.ObjectType,
		Class:          a.Class,
		Category:       a.Category,
		Family:         a.Family,
		Group:          a.Group,
		Order:          a.Order,
		Kind:           a.Kind,
		MainAttributes: a.MainAttributes,
	}

	id, _, err := assetForID.CalculateID()
	return id, err
}

func (a Asset) assetToAssetSource() AssetSource {
	return AssetSource{
		TenantID:       a.TenantID,
		SourceID:       a.SourceID,
		AssetID:        a.AssetID,
		TTL:            a.TTL,
		ExpirationTime: a.ExpirationTime,
		Tags:           a.Tags,
		Confidence:     a.Confidence,
		Attributes:     a.Attributes,
	}
}

func (a Asset) createNewCollectionFromAsset() AssetCollection {
	return AssetCollection{
		SchemaVersion:          a.SchemaVersion,
		AssetType:              a.AssetType,
		AssetTypeSchemaVersion: a.AssetTypeSchemaVersion,
		PermissionType:         a.PermissionType,
		PermissionGroupID:      a.PermissionGroupID,
		Name:                   a.Name,
		Class:                  a.Class,
		Category:               a.Category,
		Family:                 a.Family,
		Group:                  a.Group,
		Order:                  a.Order,
		Kind:                   a.Kind,
		MainAttributes:         a.MainAttributes,
		ObjectType:             a.GetObjectType(),
	}
}

// CreateAssetsCollections groups a list of assets (Assets) into AssetCollections.
// Each Asset is associated with an AssetCollection based on all of the AssetCollection's fields aside of "Sources".
// The Asset is then stripped from the common features of the AssetCollection it belongs to and is appended to AssetCollection.Sources as AssetSource.
// The max number of the assetCollections returned is the limit received.
// The returned int is the index of the asset in the assets list which we stopped on when we reached to the limit of the assetsCollections number.
// Error should not be returned in this method
func (a Assets) CreateAssetsCollections(ctx context.Context, lt *LogTrail, limit int, sortBy *string) (AssetCollections, int, error) {
	if sortBy != nil {
		// sort the received assets
		if err := a.SortBy(*sortBy); err != nil {
			lt.LogErrorf(ctx, "eda6083a-9758-4f31-bda2-c31ce0f57554", log.Fields{}, "Oh No! Create Assets Collections failed to sort assets by %s. This should never happen!!", *sortBy)
			return AssetCollections{}, 0, errors.Wrapf(err, "Failed to sort assets by %s", *sortBy)
		}
	}

	collectionMap := map[string]AssetCollection{}

	// In case the collection's number hasn't reached the limit, return the number of assets received
	assetIndex := len(a)

	for i, ast := range a {
		// Step 1: Calculate the collectionID for the asset in order to find the AssetCollection it belongs to
		collectionID, err := ast.calcCollectionID(ctx)
		if err != nil {
			// If failed to calculate collectionID --> asset would be in its own collection, using "i" as a unique collection id.
			lt.LogWarnf(ctx, "9a6cef87-2497-4c68-a7ec-8a7bd498be13", log.Fields{}, "Failed to calculate collection ID: %s", err.Error())
			collectionID = fmt.Sprintf("%d", i)
		}

		// Step 2: Add the asset to an existing collection or
		// create a new one if no matching collection was found, as long as number of collections wasn't reached the limit
		collection, ok := collectionMap[collectionID]
		if !ok {
			// Collection hasn't been created yet, if the collections number reaches the limit -> end assets iteration
			if len(collectionMap) == limit {
				assetIndex = i
				break
			}
			// Otherwise -> create a new collection
			collection = ast.createNewCollectionFromAsset()
		}

		collection.Sources = append(collection.Sources, ast.assetToAssetSource())
		collectionMap[collectionID] = collection
	}

	// Step 3: Iterate over the collectionID map to create the returned AssetCollections
	res := AssetCollections{}
	for _, collection := range collectionMap {
		res = append(res, collection)
	}

	if sortBy != nil {
		// sort the collections
		if err := res.SortBy(*sortBy); err != nil {
			lt.LogErrorf(ctx, "174f8202-de61-4359-b466-7cb07b5a9d74", log.Fields{}, "Oh No! Create Assets Collections failed to sort assets collections by %s. This should never happen!!", *sortBy)
			return AssetCollections{}, 0, errors.Wrapf(err, "Failed to sort assets collections by %s", *sortBy)
		}
	}

	lt.LogDebugf(ctx, "57900945-f2c2-44e9-a58f-318c8033ca3d", log.Fields{}, "Grouped %d assets out of %d assets into %d AssetCollections: %+v, asset index returned: %d", assetIndex, len(a), len(res), res, assetIndex)
	return res, assetIndex, nil
}

// String implements the Stringer interface. It instructs how to print the AssetSource struct while using %+v, %v or %s
func (a AssetSource) String() string {
	if a.ExpirationTime != nil {
		return fmt.Sprintf("{TenantID: %s, SourceID: %s, AssetID: %s, TTL: %d, ExpirationTime: %+v, Tags: %+v, Confidence: %d, Attributes: %+v}", a.TenantID, a.SourceID, a.AssetID, a.TTL, *a.ExpirationTime, a.Tags, a.Confidence, a.Attributes)
	}
	return fmt.Sprintf("{TenantID: %s, SourceID: %s, AssetID: %s, TTL: %d, ExpirationTime: <nil>, Tags: %+v, Confidence: %d, Attributes: %+v}", a.TenantID, a.SourceID, a.AssetID, a.TTL, a.Tags, a.Confidence, a.Attributes)
}

// SortBy sort assetCollections by any field except MainAttributes & Sources
func (a AssetCollections) SortBy(sortByField string) error {
	switch sortByField {
	case FieldSchemaVersion:
		sort.Slice(a, func(i, j int) bool { return a[i].SchemaVersion < a[j].SchemaVersion })
		return nil
	case FieldAssetType:
		sort.Slice(a, func(i, j int) bool { return a[i].AssetType < a[j].AssetType })
		return nil
	case FieldAssetTypeSchemaVersion:
		sort.Slice(a, func(i, j int) bool { return a[i].AssetTypeSchemaVersion < a[j].AssetTypeSchemaVersion })
		return nil
	case FieldPermissionType:
		sort.Slice(a, func(i, j int) bool { return a[i].PermissionType < a[j].PermissionType })
		return nil
	case FieldPermissionGroupID:
		sort.Slice(a, func(i, j int) bool { return a[i].PermissionGroupID < a[j].PermissionGroupID })
		return nil
	case FieldName:
		sort.Slice(a, func(i, j int) bool { return a[i].Name < a[j].Name })
		return nil
	case FieldClass:
		sort.Slice(a, func(i, j int) bool { return a[i].Class < a[j].Class })
		return nil
	case FieldCategory:
		sort.Slice(a, func(i, j int) bool { return a[i].Category < a[j].Category })
		return nil
	case FieldFamily:
		sort.Slice(a, func(i, j int) bool { return a[i].Family < a[j].Family })
		return nil
	case FieldGroup:
		sort.Slice(a, func(i, j int) bool { return a[i].Group < a[j].Group })
		return nil
	case FieldOrder:
		sort.Slice(a, func(i, j int) bool { return a[i].Order < a[j].Order })
		return nil
	case FieldKind:
		sort.Slice(a, func(i, j int) bool { return a[i].Kind < a[j].Kind })
		return nil
	case FieldObjectType:
		sort.Slice(a, func(i, j int) bool { return a[i].ObjectType < a[j].ObjectType })
		return nil
	default:
		return errors.Errorf("Failed to sort assets collections, unsupported sortBy field: %s", sortByField)
	}
}

// ExtractAssetsTypeFields returns new AssetTypeFieldsList with all the `fields` from the asset collections
func (a AssetCollections) ExtractAssetsTypeFields(fields []string) AssetTypeFieldsList {
	assetTypesFields := AssetTypeFieldsList{}
	assetTypesMap := make(map[string]struct{}, len(a))

	for _, collection := range a {
		fields, key := collection.extractAssetTypeFields(fields)
		// if this asset type already in the map -> ignore them
		if _, ok := assetTypesMap[key]; ok {
			continue
		}

		assetTypesMap[key] = struct{}{}
		assetTypesFields = append(assetTypesFields, fields)
	}

	return assetTypesFields
}

// extractAssetTypeFields return an AssetTypeFields struct with the asset collection values at the received `fields`,
// and a string which is some key representation for the values of the fields returned.
func (a AssetCollection) extractAssetTypeFields(fields []string) (AssetTypeFields, string) {
	assetTypeFields := AssetTypeFields{}
	key := ""
	for _, field := range fields {
		switch field {
		case assetTypeObjectTypeField:
			if a.ObjectType != "" {
				assetTypeFields.ObjectType = a.ObjectType
				key += string(a.ObjectType) + ":"
			}
		case assetTypeClassField:
			if a.Class != "" {
				assetTypeFields.Class = a.Class
				key += a.Class + ":"
			}
		case assetTypeCategoryField:
			if a.Category != "" {
				assetTypeFields.Category = a.Category
				key += a.Category + ":"
			}
		case assetTypeFamilyField:
			if a.Family != "" {
				assetTypeFields.Family = a.Family
				key += a.Family + ":"
			}
		case assetTypeGroupField:
			if a.Group != "" {
				assetTypeFields.Group = a.Group
				key += a.Group + ":"
			}
		case assetTypeOrderField:
			if a.Order != "" {
				assetTypeFields.Order = a.Order
				key += a.Order + ":"
			}
		case assetTypeKindField:
			if a.Kind != "" {
				assetTypeFields.Kind = a.Kind
				key += a.Kind + ":"
			}
		}
	}

	return assetTypeFields, key
}
