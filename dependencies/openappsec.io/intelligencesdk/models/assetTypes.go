package models

const (
	assetTypeObjectTypeField = "objectType"
	assetTypeClassField      = "class"
	assetTypeCategoryField   = "category"
	assetTypeFamilyField     = "family"
	assetTypeGroupField      = "group"
	assetTypeOrderField      = "order"
	assetTypeKindField       = "kind"
)

// AssetTypeFields contains all the fields that defined an asset type
type AssetTypeFields struct {
	ObjectType ObjectType
	Class      string
	Category   string
	Family     string
	Group      string
	Order      string
	Kind       string
}

// AssetTypeFieldsList is a list of AssetTypeFields
type AssetTypeFieldsList []AssetTypeFields

// CheckForMissingFields check for the necessary missing fields in the asset type fields
// Starts from the last field. If the field has value -> Check that all the fields above him in the hierarchy have also a value.
// Returns those fields who were missing in the hierarchy check.
// The hierarchy: Class -> Category -> Family -> Group -> Order -> Kind
// For example: `Kind` doesn't have a value, `Order` has a value -> Check for all fields except `Kind` because it's
// below `Order` in the hierarchy, which means `Kind` is not necessary for `Order`.
// in any case -> check for the ObjectType field.
// Returns true if some asset type field exist, otherwise returns false.
func (fields *AssetTypeFields) CheckForMissingFields() (bool, []string) {
	missingFields := make([]string, 0)
	if fields.Kind != "" {
		fields.checkForObjectType(&missingFields).checkForClass(&missingFields).checkForCategory(&missingFields).checkForFamily(&missingFields).checkForGroup(&missingFields).checkForOrder(&missingFields)
		return true, missingFields
	}

	if fields.Order != "" {
		fields.checkForObjectType(&missingFields).checkForClass(&missingFields).checkForCategory(&missingFields).checkForFamily(&missingFields).checkForGroup(&missingFields)
		return true, missingFields
	}

	if fields.Group != "" {
		fields.checkForObjectType(&missingFields).checkForClass(&missingFields).checkForCategory(&missingFields).checkForFamily(&missingFields)
		return true, missingFields
	}

	if fields.Family != "" {
		fields.checkForObjectType(&missingFields).checkForClass(&missingFields).checkForCategory(&missingFields)
		return true, missingFields
	}

	if fields.Category != "" {
		fields.checkForObjectType(&missingFields).checkForClass(&missingFields)
		return true, missingFields
	}

	if fields.Class != "" {
		fields.checkForObjectType(&missingFields)
		return true, missingFields
	}

	// all fields are empty, returns false.
	return false, []string{}
}

func (fields *AssetTypeFields) checkForObjectType(missingFields *[]string) *AssetTypeFields {
	if fields.ObjectType == "" {
		*missingFields = append(*missingFields, assetTypeObjectTypeField)
	}
	return fields
}

func (fields *AssetTypeFields) checkForClass(missingFields *[]string) *AssetTypeFields {
	if fields.Class == "" {
		*missingFields = append(*missingFields, assetTypeClassField)
	}
	return fields
}

func (fields *AssetTypeFields) checkForCategory(missingFields *[]string) *AssetTypeFields {
	if fields.Category == "" {
		*missingFields = append(*missingFields, assetTypeCategoryField)
	}
	return fields
}

func (fields *AssetTypeFields) checkForFamily(missingFields *[]string) *AssetTypeFields {
	if fields.Family == "" {
		*missingFields = append(*missingFields, assetTypeFamilyField)
	}
	return fields
}

func (fields *AssetTypeFields) checkForGroup(missingFields *[]string) *AssetTypeFields {
	if fields.Group == "" {
		*missingFields = append(*missingFields, assetTypeGroupField)
	}
	return fields
}

func (fields *AssetTypeFields) checkForOrder(missingFields *[]string) *AssetTypeFields {
	if fields.Order == "" {
		*missingFields = append(*missingFields, assetTypeOrderField)
	}
	return fields
}

// MergeAssetTypeFields copy the newFields that has values to each AssetTypeFields in the list.
// Assuming that if there is a new filed with value, the same field in each AssetTypeFields in the list is empty.
func (fieldsList *AssetTypeFieldsList) MergeAssetTypeFields(newFields AssetTypeFields) {
	// using regular for loop, since `range` loop is using a copy of the elements and we want to change them
	for i := 0; i < len(*fieldsList); i++ {
		(*fieldsList)[i].MergeAssetTypeFields(newFields)
	}
}

// MergeAssetTypeFields copy the newFields that have values to the AssetTypeFields.
// Assuming that if there is a new filed with value, the same field in the current fields is empty.
func (fields *AssetTypeFields) MergeAssetTypeFields(newFields AssetTypeFields) {
	if newFields.ObjectType != "" {
		fields.ObjectType = newFields.ObjectType
	}
	if newFields.Class != "" {
		fields.Class = newFields.Class
	}
	if newFields.Category != "" {
		fields.Category = newFields.Category
	}
	if newFields.Family != "" {
		fields.Family = newFields.Family
	}
	if newFields.Group != "" {
		fields.Group = newFields.Group
	}
	if newFields.Order != "" {
		fields.Order = newFields.Order
	}
	if newFields.Kind != "" {
		fields.Kind = newFields.Kind
	}
}

// ValidateAndFix returns a new list of all the assetTypeFields after validation
func (fieldsList AssetTypeFieldsList) ValidateAndFix() AssetTypeFieldsList {
	newList := AssetTypeFieldsList{}
	for _, fields := range fieldsList {
		if success := fields.validateAndFix(); success {
			newList = append(newList, fields)
		}
	}

	return newList
}

// validateAndFix returns true if AssetTypeFields is valid, or if we were able to remove fields and make it valid, otherwise returns false
// Valid AssetTypeFields is AssetTypeFields that contains all the fields from the lowest field with value till the first field in the struct.
// "Fixing" AssetTypeFields by set zero values in all the fields from the first missing field all the way down to the last field in the struct.
// if ObjectType field is missing, set it to be the default object type - 'asset'.
func (fields *AssetTypeFields) validateAndFix() bool {
	// if class is missing, AssetTypeFields is invalid
	if fields.Class == "" {
		return false
	}

	if fields.ObjectType == "" {
		fields.ObjectType = DefaultObjectType
	}

	if fields.Category == "" {
		fields.Family = ""
		fields.Group = ""
		fields.Order = ""
		fields.Kind = ""
		return true
	}

	if fields.Family == "" {
		fields.Group = ""
		fields.Order = ""
		fields.Kind = ""
		return true
	}

	if fields.Group == "" {
		fields.Order = ""
		fields.Kind = ""
		return true
	}

	if fields.Order == "" {
		fields.Kind = ""
		return true
	}

	// if just Kind is missing, nothing need to change
	return true
}
