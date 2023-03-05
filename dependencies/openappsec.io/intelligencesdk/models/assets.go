package models

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"openappsec.io/errors"
	"openappsec.io/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Asset field name consts
const (
	FieldTenantID               = "tenantId"
	FieldSourceID               = "sourceId"
	FieldAssetID                = "assetId"
	FieldTTL                    = "ttl"
	FieldExpirationTime         = "expirationTime"
	FieldMainAttributes         = "mainAttributes"
	FieldAttributes             = "attributes"
	FieldTags                   = "tags"
	FieldName                   = "name"
	FieldClass                  = "class"
	FieldCategory               = "category"
	FieldFamily                 = "family"
	FieldFunction               = "function"
	FieldConfidence             = "confidence"
	FieldVersion                = "version"
	FieldSchemaVersion          = "schemaVersion"
	FieldAssetType              = "assetType"
	FieldAssetTypeSchemaVersion = "assetTypeSchemaVersion"
	FieldPermissionType         = "permissionType"
	FieldPermissionGroupID      = "permissionGroupId"
	FieldGroup                  = "group"
	FieldOrder                  = "order"
	FieldKind                   = "kind"
	FieldObjectType             = "objectType"
	FieldRevokedAt              = "revokedAt"
)

const (
	// AssetVersion the current asset version
	AssetVersion = "v1"

	// MainAttributeKeyIP represents the mainAttributes ip field in an asset
	MainAttributeKeyIP = "ip"
	// DefaultMinConfidence is the default min confidence of an intelligence query
	DefaultMinConfidence = 500
	// DefaultPaginationLimit is the default pagination limit for returned assets
	DefaultPaginationLimit = 20
)

// Asset PermissionType types
const (
	AssetPermissionTypeAllTenants = "allTenants"
	AssetPermissionTypePublic     = "public"
	AssetPermissionTypeTenant     = "tenant"
)

const (
	threatCloudAssetType = "data-threatcloud-ip"
	// allowed non-mutually exclusive main-attributes and attributes keys for threatCloud assets
	threatCloudKeyGeneralIP     = "ip"
	threatCloudKeyIpv4Addresses = "ipv4Addresses"
	threatCloudKeyIpv6Addresses = "ipv6Addresses"
)

// ipAddresses consts
const (
	attributesPrefix                = FieldAttributes + "."
	ipv4Addresses                   = "ipv4Addresses"
	ipv4AddressesRange              = ipv4Addresses + Range
	AttributesIPv4Addresses         = attributesPrefix + ipv4Addresses
	AttributesIPv4AddressesRange    = attributesPrefix + ipv4AddressesRange
	AttributesIPv4AddressesRangeMin = AttributesIPv4AddressesRange + "." + Min
	AttributesIPv4AddressesRangeMax = AttributesIPv4AddressesRange + "." + Max
	ipv6Addresses                   = "ipv6Addresses"
	ipv6AddressesRange              = ipv6Addresses + Range
	AttributesIPv6Addresses         = attributesPrefix + ipv6Addresses
	AttributesIPv6AddressesRange    = attributesPrefix + ipv6AddressesRange
	AttributesIPv6AddressesRangeMin = AttributesIPv6AddressesRange + "." + Min
	AttributesIPv6AddressesRangeMax = AttributesIPv6AddressesRange + "." + Max
	ports                           = "ports"
	portsRange                      = ports + Range
	AttributesPorts                 = attributesPrefix + ports
	AttributesPortsRange            = attributesPrefix + portsRange
	AttributesPortsRangeMin         = AttributesPortsRange + "." + Min
	AttributesPortsRangeMax         = AttributesPortsRange + "." + Max
	Range                           = "Range"
	Min                             = "min"
	Max                             = "max"
	IPv6AddressesRangeCollation     = "en_US"
)

// Assets is a list made of Asset items
type Assets []Asset

// AssetRootMandatoryFields fields that always show up in the asset root and the user may not place inside the attributes section
var AssetRootMandatoryFields = []string{FieldTTL, FieldClass, FieldCategory, FieldFamily, FieldConfidence, FieldMainAttributes,
	FieldSchemaVersion, FieldAssetType, FieldAssetTypeSchemaVersion, FieldPermissionType}

// Asset is a representation of a single asset
// Explanation about AssetID and AssetIDReversible:
// In the mongoDB - AssetID contains the sha of the AssetIDReversible field, which is the real asset ID
// For the client - AssetID contains the value of AssetIDReversible field and AssetIDReversible field is empty
type Asset struct {
	SchemaVersion          int                    `json:"schemaVersion,omitempty" bson:"schemaVersion,omitempty"`
	TTL                    int                    `json:"ttl,omitempty" bson:"ttl,omitempty"`
	AssetType              string                 `json:"assetType,omitempty" bson:"assetType,omitempty"`
	AssetTypeSchemaVersion int                    `json:"assetTypeSchemaVersion,omitempty" bson:"assetTypeSchemaVersion,omitempty"`
	PermissionType         string                 `json:"permissionType,omitempty" bson:"permissionType,omitempty"`
	PermissionGroupID      string                 `json:"permissionGroupId,omitempty" bson:"permissionGroupId,omitempty"`
	Name                   string                 `json:"name,omitempty" bson:"name,omitempty"`
	ObjectType             ObjectType             `json:"objectType,omitempty" bson:"objectType,omitempty"`
	Class                  string                 `json:"class,omitempty" bson:"class,omitempty"`
	Category               string                 `json:"category,omitempty" bson:"category,omitempty"`
	Family                 string                 `json:"family,omitempty" bson:"family,omitempty"`
	Group                  string                 `json:"group,omitempty" bson:"group,omitempty"`
	Order                  string                 `json:"order,omitempty" bson:"order,omitempty"`
	Kind                   string                 `json:"kind,omitempty" bson:"kind,omitempty"`
	TenantID               string                 `json:"tenantId,omitempty" bson:"tenantId,omitempty"`
	SourceID               string                 `json:"sourceId,omitempty" bson:"sourceId,omitempty"`
	AgentID                string                 `json:"agentId,omitempty" bson:"agentId,omitempty"`
	AssetID                string                 `json:"assetId,omitempty" bson:"assetId,omitempty"`
	AssetIDReversible      string                 `json:"assetIDReversible,omitempty" bson:"assetIDReversible,omitempty"`
	Version                string                 `json:"version,omitempty" bson:"version,omitempty"`
	ExpirationTime         *time.Time             `json:"expirationTime,omitempty" bson:"expirationTime,omitempty"`
	Tags                   map[string]string      `json:"tags,omitempty" bson:"tags,omitempty"`
	Confidence             int                    `json:"confidence,omitempty" bson:"confidence,omitempty"`
	MainAttributes         MainAttributes         `json:"mainAttributes,omitempty" bson:"mainAttributes,omitempty"`
	Attributes             map[string]interface{} `json:"attributes,omitempty" bson:"attributes,omitempty"`
	Function               string                 `json:"function,omitempty" bson:"function,omitempty"` // using for legacy
}

// AssetsForInvalidation represents the repository assets and the invalidation assets that are used during the invalidation process
type AssetsForInvalidation struct {
	AssetsFromRepo     Assets `json:"assetsFromRepo,omitempty"`
	AssetsFromInvalReq Assets `json:"assetsFromInvalReq,omitempty"`
}

// RangeMap represents the repository ip addresses and port range struct
type RangeMap map[string]interface{}

// RangeMaps represents the repository ip addresses and ports range struct
type RangeMaps []RangeMap

// IPAddressRangeV4FromRepo represents the repository ip address range struct
type IPAddressRangeV4FromRepo map[string]int

// IPAddressesRangeV4FromRepo represents the repository ip addresses range struct
type IPAddressesRangeV4FromRepo []IPAddressRangeV4FromRepo

// IPAddressRangeV6FromRepo represents the repository ip address range struct
type IPAddressRangeV6FromRepo map[string]string

// IPAddressesRangeV6FromRepo represents the repository ip addresses range struct
type IPAddressesRangeV6FromRepo []IPAddressRangeV6FromRepo

// String implements the Stringer interface. It instructs how to print the Asset struct while using %+v, %v or %s
func (a Asset) String() string {
	if a.ExpirationTime != nil {
		return fmt.Sprintf("{SchemaVersion: %d, TTL: %d, AssetType: %s, AssetTypeSchemaVersion: %d, PermissionType: %s, PermissionGroupID: %s, Name: %s, ObjectType: %s, Class: %s, Category: %s, Family: %s, Group: %s, Order: %s, Kind: %s, TenantID: %s, SourceID: %s, AssetID: %s, Version: %s, ExpirationTime: %+v, Tags: %+v, Confidence: %d, MainAttributes: %+v, Attributes: %+v, Function: %s}", a.SchemaVersion, a.TTL, a.AssetType, a.AssetTypeSchemaVersion, a.PermissionType, a.PermissionGroupID, a.Name, a.ObjectType, a.Class, a.Category, a.Family, a.Group, a.Order, a.Kind, a.TenantID, a.SourceID, a.AssetID, a.Version, *a.ExpirationTime, a.Tags, a.Confidence, a.MainAttributes, a.Attributes, a.Function)
	}
	return fmt.Sprintf("{SchemaVersion: %d, TTL: %d, AssetType: %s, AssetTypeSchemaVersion: %d, PermissionType: %s, PermissionGroupID: %s, Name: %s, ObjectType: %s, Class: %s, Category: %s, Family: %s, Group: %s, Order: %s, Kind: %s, TenantID: %s, SourceID: %s, AssetID: %s, Version: %s, ExpirationTime: <nil>, Tags: %+v, Confidence: %d, MainAttributes: %+v, Attributes: %+v, Function: %s}", a.SchemaVersion, a.TTL, a.AssetType, a.AssetTypeSchemaVersion, a.PermissionType, a.PermissionGroupID, a.Name, a.ObjectType, a.Class, a.Category, a.Family, a.Group, a.Order, a.Kind, a.TenantID, a.SourceID, a.AssetID, a.Version, a.Tags, a.Confidence, a.MainAttributes, a.Attributes, a.Function)
}

// Copy accepts an asset and returns an identical replica with all values copied
// TODO - handle recursive (deep) copy of attributes section.
func (a Asset) Copy() (Asset, error) {
	cpy := a
	if a.ExpirationTime != nil {
		t := time.Unix(a.ExpirationTime.Unix(), 0).UTC()
		cpy.ExpirationTime = &t
	}

	copyMap := func(m map[string]string) map[string]string {
		var cm = make(map[string]string, len(m))
		for k, v := range m {
			cm[k] = v
		}
		return cm
	}

	if a.Tags != nil {
		cpy.Tags = copyMap(a.Tags)
	}

	if a.MainAttributes != nil {
		cpyMainAtt, err := a.MainAttributes.Copy()
		if err != nil {
			return Asset{}, errors.Wrap(err, "Failed to copy asset")
		}
		cpy.MainAttributes = cpyMainAtt
	}

	if a.Attributes != nil {
		cpy.Attributes = make(map[string]interface{}, len(a.Attributes))
		for k, v := range a.Attributes {
			cpy.Attributes[k] = v
		}
	}

	return cpy, nil
}

// EnrichAsset enrich an asset with more information
func (a *Asset) EnrichAsset(ctx context.Context, tenantID string, sourceID string) error {
	if a.ObjectType == "" {
		a.ObjectType = DefaultObjectType
	}

	apiV, err := GetAPIVersionFromContext(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed to get API version from context")
	}

	var id string
	var idSha string
	if apiV == APILegacy {
		id, err = a.CalculateIDLegacy()
		// ATTENTION - for legacy the asset is NOT reversible
		idSha = id
		if err != nil {
			return errors.Wrap(err, "Failed to create legacy asset ID")
		}
	} else {
		id, idSha, err = a.CalculateID()
		if err != nil {
			return errors.Wrap(err, "Failed to create asset ID")
		}
	}

	a.AssetID = idSha
	a.AssetIDReversible = id
	a.TenantID = tenantID
	a.SourceID = sourceID
	a.Version = AssetVersion
	t := time.Now().Add(time.Duration(a.TTL) * time.Second).UTC()
	a.ExpirationTime = &t

	if a.Name == "" {
		if err := a.NameAsset(); err != nil {
			return errors.Wrap(err, "Failed to name asset")
		}
	}

	err = a.enrichRangeAttributes()
	if err != nil {
		return errors.Wrap(err, "Field to enrich asset with ip addresses fields")
	}

	return nil
}

// NameAsset create name for the asset by concat of all its mainAttributes values
func (a *Asset) NameAsset() error {
	keys := make([]string, 0, len(a.MainAttributes))
	for k := range a.MainAttributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	values := make([]string, 0)
	sortedMainAttributes, err := a.MainAttributes.Sort()
	if err != nil {
		return errors.Wrapf(err, "Failed to sort MainAttributes")
	}

	for _, k := range keys {
		values = append(values, fmt.Sprintf("%v", sortedMainAttributes[k]))
	}

	a.Name = strings.Join(values, "-")
	return nil
}

// Diet acts on a list of assets and returns a new list where each asset has just the informative fields for logging
func (a Assets) Diet() Assets {
	var res Assets
	for _, ass := range a {
		res = append(res, ass.Diet())
	}

	return res
}

// Diet acts on an asset and returns a new asset with just its main fields
func (a Asset) Diet() Asset {
	var res Asset
	res.MainAttributes = a.MainAttributes
	res.TenantID = a.TenantID
	res.SourceID = a.SourceID
	res.Class = a.Class
	res.Category = a.Category
	res.Family = a.Family
	res.Group = a.Group
	res.Order = a.Order
	res.Kind = a.Kind
	res.AssetID = a.AssetID
	res.AssetIDReversible = a.AssetIDReversible
	res.ObjectType = a.ObjectType
	return res
}

// RemoveInternalFieldsLegacy removes fields inside the asset that we do not want the user to see
// Legacy function - also includes assetId
func (a *Asset) RemoveInternalFieldsLegacy() {
	a.RemoveInternalFields()
	a.AssetID = ""
	a.AssetIDReversible = ""
}

// RemoveInternalFields removes fields inside the asset that we do not want the user to see
func (a *Asset) RemoveInternalFields() {
	a.Version = ""
	a.AssetIDReversible = ""
}

// RemoveInternalFields removes fields inside each asset that we do not want the user to see
func (a *Assets) RemoveInternalFields() {
	for _, asset := range *a {
		asset.RemoveInternalFields()
	}
}

// ValidateAssetMutualExclusivity fields that show up in the asset root and main attributes must not show up in attributes
func (a Asset) ValidateAssetMutualExclusivity() error {
	mainAttributes := a.MainAttributes
	attributes := a.Attributes

	for k := range mainAttributes {
		if a.AssetType == threatCloudAssetType {
			switch k {
			case threatCloudKeyGeneralIP, threatCloudKeyIpv4Addresses, threatCloudKeyIpv6Addresses:
				continue
			}
		}
		if _, ok := attributes[k]; ok {
			return errors.Errorf("Key (%s) can't exist both in %s and %s", k, FieldMainAttributes, FieldAttributes).SetClass(errors.ClassBadInput)
		}
	}

	root := AssetRootMandatoryFields
	if a.Name != "" {
		root = append(root, FieldName)
	}

	if a.Tags != nil {
		root = append(root, FieldTags)
	}

	if a.Attributes != nil {
		root = append(root, FieldAttributes)
	}

	if a.Group != "" {
		root = append(root, FieldGroup)
	}

	if a.Order != "" {
		root = append(root, FieldOrder)
	}

	if a.Kind != "" {
		root = append(root, FieldKind)
	}

	if a.PermissionGroupID != "" {
		root = append(root, FieldPermissionGroupID)
	}

	if a.ObjectType != "" {
		root = append(root, FieldNameObjectType)
	}

	// using for legacy
	if a.Function != "" {
		root = append(root, FieldFunction)
	}

	for _, k := range root {
		if _, ok := a.Attributes[k]; ok {
			return errors.Errorf("Key (%s) can't exist both in root and %s", k, FieldAttributes).SetClass(errors.ClassBadInput)
		}
	}

	return nil
}

// ValidatePermissionType only known sources can report assets of permission type `allTenants`
func (a Asset) ValidatePermissionType(knownSources KnownAllTenantsSources) error {
	if a.PermissionType == AssetPermissionTypeAllTenants {
		if _, ok := knownSources[a.TenantID]; !ok {
			return errors.Errorf("Key `PermissionType` supports only '%s' value, given: %s", AssetPermissionTypeTenant, a.PermissionType).SetClass(errors.ClassBadInput)
		}

		return nil
	}

	if a.PermissionType != AssetPermissionTypeTenant {
		return errors.Errorf("Key `PermissionType` supports only '%s' value, given: %s", AssetPermissionTypeTenant, a.PermissionType).SetClass(errors.ClassBadInput)
	}

	return nil
}

// ApplyUpdate modifies the acted upon asset to reflect the desired updates in the given AssetUpdate
func (a *Asset) ApplyUpdate(updates AssetUpdate) error {
	for k, v := range updates {
		kys := strings.Split(k, ".")
		if len(kys) < 1 || len(kys) > 2 {
			return errors.Errorf("Invalid split array size (%v) created from %s, should be 1 or 2", len(kys), k)
		}

		switch k := kys[0]; k {
		case FieldObjectType:
			a.ObjectType = v.(ObjectType)
		case FieldTTL:
			a.TTL = int(v.(float64))
		case FieldExpirationTime:
			et := v.(time.Time)
			a.ExpirationTime = &et
		case FieldSchemaVersion:
			a.SchemaVersion = int(v.(float64))
		case FieldAssetType:
			a.AssetType = v.(string)
		case FieldAssetTypeSchemaVersion:
			a.AssetTypeSchemaVersion = int(v.(float64))
		case FieldPermissionType:
			a.PermissionType = v.(string)
		case FieldPermissionGroupID:
			a.PermissionGroupID = v.(string)
		case FieldName:
			a.Name = v.(string)
		case FieldClass:
			a.Class = v.(string)
		case FieldCategory:
			a.Category = v.(string)
		case FieldFamily:
			a.Family = v.(string)
		case FieldGroup:
			a.Group = v.(string)
		case FieldOrder:
			a.Order = v.(string)
		case FieldKind:
			a.Kind = v.(string)
		case FieldFunction: // using for legacy
			a.Kind = v.(string)
		case FieldConfidence:
			a.Confidence = int(v.(float64))
		case FieldTags:
			if a.Tags == nil {
				a.Tags = make(map[string]string)
			}

			if len(kys) == 1 {
				for tk, tv := range v.(map[string]interface{}) {
					a.Tags[tk] = tv.(string)
				}
			} else {
				a.Tags[kys[1]] = v.(string)
			}
		case FieldAttributes:
			if len(kys) == 1 {
				a.Attributes = v.(map[string]interface{})
			} else {
				if a.Attributes == nil {
					a.Attributes = make(map[string]interface{})
				}
				a.Attributes[kys[1]] = v
			}
		default:
			return errors.Errorf("Unsupported update asset field (%s)", k).SetClass(errors.ClassBadInput)
		}
	}

	return nil
}

// SortBy sort assets by any AssetCollections field except MainAttributes & Sources
func (a Assets) SortBy(sortByField string) error {
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
	default:
		return errors.Errorf("Failed to sort assets, unsupported sortBy field: %s", sortByField)
	}

	return nil
}

// AssetForInvalidation create an asset containing only the fields needed for invalidation
func (a Asset) AssetForInvalidation() Asset {
	return Asset{
		MainAttributes: a.MainAttributes,
		ObjectType:     a.ObjectType,
		Class:          a.Class,
		Category:       a.Category,
		Family:         a.Family,
		Group:          a.Group,
		Order:          a.Order,
		Kind:           a.Kind,
		TenantID:       a.TenantID,
	}
}

// ExtractAssetsTypeFields returns new AssetTypeFieldsList with all the `fields` from the assets
func (a Assets) ExtractAssetsTypeFields(fields []string) AssetTypeFieldsList {
	assetTypesFields := AssetTypeFieldsList{}
	assetTypesMap := make(map[string]struct{}, len(a))

	for _, asset := range a {
		fields, key := asset.extractAssetTypeFields(fields)
		// if this asset type already in the map -> ignore it
		if _, ok := assetTypesMap[key]; ok {
			continue
		}

		assetTypesMap[key] = struct{}{}
		assetTypesFields = append(assetTypesFields, fields)
	}

	return assetTypesFields
}

// extractAssetTypeFields return an AssetTypeFields struct with the asset values at the received `fields`,
// and a string which is some key representation for the values of the fields returned.
func (a Asset) extractAssetTypeFields(fields []string) (AssetTypeFields, string) {
	assetTypeFields := AssetTypeFields{}
	// The key is concatenation of all the fields with ':' between them and at the end of the key.
	// This key is only for INTERNAL use, to make sure we don't have duplications.
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

// GetAssetTypeFields return AssetTypeFields struct with the asset data
func (a Asset) GetAssetTypeFields() AssetTypeFields {
	return AssetTypeFields{
		ObjectType: a.ObjectType,
		Class:      a.Class,
		Category:   a.Category,
		Family:     a.Family,
		Group:      a.Group,
		Order:      a.Order,
		Kind:       a.Kind,
	}
}

// GetObjectType returns the object type if detailed in the asset - else returns the default object type
func (a Asset) GetObjectType() ObjectType {
	if a.ObjectType == "" {
		return DefaultObjectType
	}

	return a.ObjectType
}

// CreateAllMatchInvalidations creates and returns all the unique invalidation data structs for the assets.
func (a Assets) CreateAllMatchInvalidations(ctx context.Context, lt *LogTrail) InvalidationsData {
	allMatchInval := make(InvalidationsData, 0)
	uniqueInval := make(map[string]struct{})
	for _, asset := range a {
		invalData := asset.CreateMatchingInvalidationData()

		if asset.AssetID == "" {
			assetID, _, err := asset.GetAssetID(ctx)
			if err != nil {
				lt.LogWarnf(ctx, "09532466-3f5f-4ad8-a899-556aaef6ef11", log.Fields{}, "Failed to get assetID with error: %s", err.Error())
				continue
			}

			asset.AssetID = assetID
		}

		if _, ok := uniqueInval[asset.AssetID]; !ok {
			uniqueInval[asset.AssetID] = struct{}{}
			allMatchInval = append(allMatchInval, invalData)
		}
	}

	return allMatchInval
}

// CreateMatchingInvalidationData returns a matching invalidation data struct for the asset
func (a Asset) CreateMatchingInvalidationData() InvalidationData {
	return InvalidationData{
		ObjectType:     a.ObjectType,
		Class:          a.Class,
		Category:       a.Category,
		Family:         a.Family,
		Group:          a.Group,
		Order:          a.Order,
		Kind:           a.Kind,
		MainAttributes: MainAttributesList{a.MainAttributes},
	}
}

// AddObjectType adds the default ObjectType to the asset in case it's missing
func (a *Asset) AddObjectType() {
	if a.ObjectType == MissingObjectType {
		a.ObjectType = DefaultObjectType
	}
}

// AssetsIDReversibleToAssetID put the reversible id in the assetId field for the client
func AssetsIDReversibleToAssetID(a Assets) Assets {
	assets := Assets{}
	for _, ass := range a {
		assets = append(assets, AssetIDReversibleToAssetID(ass))
	}

	return assets
}

// AssetIDReversibleToAssetID put the reversible id in the assetId field for the client
func AssetIDReversibleToAssetID(a Asset) Asset {
	if len(a.AssetIDReversible) > 0 {
		a.AssetID = a.AssetIDReversible
	}

	a.AssetIDReversible = ""
	return a
}

func (a *Asset) enrichRangeAttributes() error {
	if len(a.Attributes) <= 0 {
		return nil
	}

	_, okIPV4Addresses := a.Attributes[ipv4Addresses]
	_, okIPV6Addresses := a.Attributes[ipv6Addresses]
	_, okPorts := a.Attributes[ports]
	_, okIPV4AddressesRange := a.Attributes[ipv4AddressesRange]
	_, okIPV6AddressesRange := a.Attributes[ipv6AddressesRange]
	_, okPortsRange := a.Attributes[portsRange]

	addAttributesRange := func(attributes, attributesRange string) error {
		// adding attributes range
		attributesArrInterface, ok := a.Attributes[attributes].([]interface{})
		if !ok {
			return errors.Errorf("Failed to assert attributes.%s as []interface{}, got %#v", attributes, a.Attributes[attributes]).SetClass(errors.ClassBadInput)
		}

		var attributesRangeStruct []interface{}
		for _, attribute := range attributesArrInterface {
			rangeInterface := RangeMap{Min: attribute, Max: attribute}

			attributesRangeStruct = append(attributesRangeStruct, rangeInterface)
		}

		a.Attributes[attributesRange] = attributesRangeStruct
		return nil
	}

	addAttributes := func(attributes, attributesRange string) error {
		// adding attributes list
		attributesRangeArr, ok := a.Attributes[attributesRange].([]interface{})
		if !ok {
			return errors.Errorf("Failed to assert attributes.%s as type []interface{}, got %#v", ipv4AddressesRange, a.Attributes[ipv4AddressesRange]).SetClass(errors.ClassBadInput)
		}

		attributesMap := make(map[interface{}]struct{})
		var attributesList []interface{}
		for _, v := range attributesRangeArr {
			attributesRangeMap, ok := v.(map[string]interface{})
			if !ok {
				return errors.Errorf("Failed to assert attributes.%s as type map[string]interface{}, got %#v", attributesRange, attributesRange).SetClass(errors.ClassBadInput)
			}

			if _, ok := attributesMap[attributesRangeMap[Min]]; !ok {
				attributesMap[attributesRangeMap[Min]] = struct{}{}
				attributesList = append(attributesList, attributesRangeMap[Min])
			}

			if _, ok := attributesMap[attributesRangeMap[Max]]; !ok {
				attributesMap[attributesRangeMap[Max]] = struct{}{}
				attributesList = append(attributesList, attributesRangeMap[Max])
			}
		}

		a.Attributes[attributes] = attributesList
		return nil
	}

	if okIPV4Addresses && !okIPV4AddressesRange {
		if err := addAttributesRange(ipv4Addresses, ipv4AddressesRange); err != nil {
			return err
		}
	}

	if okIPV6Addresses && !okIPV6AddressesRange {
		if err := addAttributesRange(ipv6Addresses, ipv6AddressesRange); err != nil {
			return err
		}
	}

	if okPorts && !okPortsRange {
		if err := addAttributesRange(ports, portsRange); err != nil {
			return err
		}
	}

	if !okIPV4Addresses && okIPV4AddressesRange {
		if err := addAttributes(ipv4Addresses, ipv4AddressesRange); err != nil {
			return err
		}
	}

	if !okIPV6Addresses && okIPV6AddressesRange {
		if err := addAttributes(ipv6Addresses, ipv6AddressesRange); err != nil {
			return err
		}
	}

	if !okPorts && okPortsRange {
		if err := addAttributes(ports, portsRange); err != nil {
			return err
		}
	}

	return nil
}

// ipAddressesRangeIntToString converts the ip address range values as received from repository from int to string
func (a *Asset) ipAddressesRangeIntToString() error {
	if len(a.Attributes) <= 0 {
		return nil
	}

	_, okIPV4AddressesRange := a.Attributes[ipv4AddressesRange]
	_, okIPV6AddressesRange := a.Attributes[ipv6AddressesRange]

	if okIPV4AddressesRange {
		ipv4AddressesRangeAttPrim, ok := a.Attributes[ipv4AddressesRange].(primitive.A)
		if !ok {
			ipv4AddressesRangeAttPrim, ok = a.Attributes[ipv4AddressesRange].([]interface{})
			if !ok {
				return errors.Errorf("Failed to assert attributes.%s as Mongo's type primitive.A, or []interface got %#v", ipv4AddressesRange, a.Attributes[ipv4AddressesRange]).SetClass(errors.ClassInternal)
			}
		}

		var stringIPRanges RangeMaps
		for _, ipRange := range ipv4AddressesRangeAttPrim {
			ipv4AddressesRangeAtt, ok := ipRange.(map[string]interface{})
			if !ok {
				return errors.Errorf("Failed to assert attributes.%s as map[string]interface{}, got %#v", ipv4AddressesRange, ipRange).SetClass(errors.ClassInternal)
			}

			minIntIP, ok := interfaceToInt(ipv4AddressesRangeAtt[Min])
			if !ok {
				return errors.Errorf("Either attributes.%s min doesn't have key %s or its value isn't of type int32 or int64 or float32 or float64, got %#v", ipv4AddressesRange, Min, ipv4AddressesRangeAtt[Min]).SetClass(errors.ClassInternal)
			}

			maxIntIP, ok := interfaceToInt(ipv4AddressesRangeAtt[Max])
			if !ok {
				return errors.Errorf("Either attributes.%s max doesn't have key %s or its value isn't of type int32 or int64 or float32 or flout64, got %#v", ipv4AddressesRange, Max, ipv4AddressesRangeAtt[Max]).SetClass(errors.ClassInternal)
			}

			stringIPRange := RangeMap{Min: IntToStringIPv4(minIntIP), Max: IntToStringIPv4(maxIntIP)}
			stringIPRanges = append(stringIPRanges, stringIPRange)
		}

		a.Attributes[ipv4AddressesRange] = stringIPRanges
	}

	if okIPV6AddressesRange {
		ipv6AddressesRangeAttPrim, ok := a.Attributes[ipv6AddressesRange].(primitive.A)
		if !ok {
			ipv6AddressesRangeAttPrim, ok = a.Attributes[ipv6AddressesRange].([]interface{})
			if !ok {
				return errors.Errorf("Failed to assert attributes.%s as Mongo's type primitive.A, or []interface got %#v", ipv6AddressesRange, a.Attributes[ipv6AddressesRange]).SetClass(errors.ClassInternal)
			}
		}

		var stringIPRanges RangeMaps
		for _, ipRange := range ipv6AddressesRangeAttPrim {
			ipv6AddressesRangeAtt, ok := ipRange.(map[string]interface{})
			if !ok {
				return errors.Errorf("Failed to assert attributes.%s as map[string]interface{}", ipv6AddressesRange).SetClass(errors.ClassInternal)
			}

			minIP, ok := ipv6AddressesRangeAtt[Min].(string)
			if !ok {
				return errors.Errorf("Either attributes.%s doesn't have key %s or its value isn't of type *big.Int", ipv6AddressesRange, Min).SetClass(errors.ClassInternal)
			}

			maxIP, ok := ipv6AddressesRangeAtt[Max].(string)
			if !ok {
				return errors.Errorf("Either attributes.%s doesn't have key %s or its value isn't of type *big.Int", ipv6AddressesRange, Max).SetClass(errors.ClassInternal)
			}

			stringIPRange := RangeMap{Min: BigIntStringToStringIPv6(minIP), Max: BigIntStringToStringIPv6(maxIP)}
			stringIPRanges = append(stringIPRanges, stringIPRange)
		}

		a.Attributes[ipv6AddressesRange] = stringIPRanges
	}

	return nil
}

// IPAddressesRangeIntToStringAssets converts the ip address range values from int to string
func (a Assets) IPAddressesRangeIntToStringAssets() (Assets, error) {
	var assets Assets
	for _, ass := range a {
		err := ass.ipAddressesRangeIntToString()
		if err != nil {
			return Assets{}, errors.Wrap(err, "Failed to convert int ip range to string")
		}

		assets = append(assets, ass)
	}

	if len(assets) <= 0 {
		assets = Assets{}
	}

	return assets, nil
}

// IPAddressesRangeStringToInt converts the ip address range values from string to int
func (a *Asset) IPAddressesRangeStringToInt() error {
	if len(a.Attributes) <= 0 {
		return nil
	}

	_, okIPV4AddressesRange := a.Attributes[ipv4AddressesRange]
	_, okIPV6AddressesRange := a.Attributes[ipv6AddressesRange]

	if okIPV4AddressesRange {
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
					return errors.Errorf("Failed to assert attributes.%s as type map[string]interface{} or type RangeMap while matching asset to query, got %#v", ipv4AddressesRange, a.Attributes[ipv4AddressesRange]).SetClass(errors.ClassBadInput)
				}
			}
		default:
			return errors.Errorf("Failed to assert attributes.%s as type []interface{} or type RangeMaps, got %#v", ipv4AddressesRange, a.Attributes[ipv4AddressesRange]).SetClass(errors.ClassBadInput)
		}

		var intIPRanges IPAddressesRangeV4FromRepo
		for _, ipRange := range ipv4AddressesRangeAttStruct {
			minIPString, ok := ipRange[Min].(string)
			if !ok {
				return errors.Errorf("Failed to assert %s as type string, got %#v", AttributesIPv4AddressesRangeMin, ipRange[Min]).SetClass(errors.ClassBadInput)
			}

			minIP, err := StringToIntIPv4(minIPString)
			if err != nil {
				return err
			}

			maxIPString, ok := ipRange[Max].(string)
			if !ok {
				return errors.Errorf("Failed to assert %s as type string, got %#v", AttributesIPv4AddressesRangeMax, ipRange[Max]).SetClass(errors.ClassBadInput)
			}

			maxIP, err := StringToIntIPv4(maxIPString)
			if err != nil {
				return err
			}

			intIPRange := IPAddressRangeV4FromRepo{Min: minIP, Max: maxIP}
			intIPRanges = append(intIPRanges, intIPRange)
		}

		a.Attributes[ipv4AddressesRange] = intIPRanges
	}

	if okIPV6AddressesRange {
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
					return errors.Errorf("Failed to assert attributes.%s as type map[string]interface{} or type RangeMap while matching asset to query, got %#v", ipv6AddressesRange, a.Attributes[ipv6AddressesRange]).SetClass(errors.ClassBadInput)
				}
			}
		default:
			return errors.Errorf("Failed to assert attributes.%s as type []interface{} or type RangeMaps, got %#v", ipv6AddressesRange, a.Attributes[ipv6AddressesRange]).SetClass(errors.ClassBadInput)
		}

		var intIPRanges RangeMaps
		for _, ipRange := range ipv6AddressesRangeAttStruct {
			minIPString, ok := ipRange[Min].(string)
			if !ok {
				return errors.Errorf("Failed to assert %s as type string, got %#v", AttributesIPv6AddressesRangeMin, ipRange[Min]).SetClass(errors.ClassBadInput)
			}

			minIP, err := StringToIntIPv6(minIPString)
			if err != nil {
				return err
			}

			maxIPString, ok := ipRange[Max].(string)
			if !ok {
				return errors.Errorf("Failed to assert %s as type string, got %#v", AttributesIPv6AddressesRangeMax, ipRange[Max]).SetClass(errors.ClassBadInput)
			}

			maxIP, err := StringToIntIPv6(maxIPString)
			if err != nil {
				return err
			}

			intIPRange := RangeMap{Min: minIP.String(), Max: maxIP.String()}
			intIPRanges = append(intIPRanges, intIPRange)
		}

		a.Attributes[ipv6AddressesRange] = intIPRanges
	}

	return nil
}

// IPAddressesRangeStringToIntAssets converts the ip address range values from string to int
func (a Assets) IPAddressesRangeStringToIntAssets() (Assets, error) {
	var assets Assets
	for _, ass := range a {
		err := ass.IPAddressesRangeStringToInt()
		if err != nil {
			return Assets{}, errors.Wrap(err, "Failed to convert int ip to string")
		}

		assets = append(assets, ass)
	}

	if len(assets) <= 0 {
		assets = Assets{}
	}

	return assets, nil
}

// AddAgentID adds the agent id to the assets
func (a *Assets) AddAgentID(agentID string) {
	for _, ass := range *a {
		ass.AgentID = agentID
	}
}

// interfaceToInt returns the int value of the given interface{} and a bool indicating if it passed the type assertion.
func interfaceToInt(i interface{}) (int, bool) {
	switch v := i.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		return int(v), true
	case float32:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}
