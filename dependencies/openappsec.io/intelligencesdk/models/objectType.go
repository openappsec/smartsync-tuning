package models

// ObjectType is the type of the object - asset | zone | ...
type ObjectType string

// ObjectTypes is an array of ObjectType
type ObjectTypes []ObjectType

// Supported object types
const (
	ObjectTypeAsset         ObjectType = "asset"
	ObjectTypeZone          ObjectType = "zone"
	ObjectTypePolicyPackage ObjectType = "policyPackage"
	ObjectTypeConfiguration ObjectType = "configuration"
	ObjectTypeSession       ObjectType = "session"
	DefaultObjectType                  = ObjectTypeAsset
	MissingObjectType       ObjectType = ""

	NumberOfSupportedObjectTypes = 3
)

// FieldNameObjectType is the object type field name in datamap
const FieldNameObjectType = "objectType"

// GetSupportedObjectTypes returns a map and a list of all the supported object types
func GetSupportedObjectTypes() (map[ObjectType]ObjectType, ObjectTypes) {
	allSupportedObjTypes := ObjectTypes{ObjectTypeAsset, ObjectTypeZone, ObjectTypePolicyPackage, ObjectTypeConfiguration, ObjectTypeSession}
	allSupportedObjTypeMap := make(map[ObjectType]ObjectType, len(allSupportedObjTypes))
	for _, objType := range allSupportedObjTypes {
		allSupportedObjTypeMap[objType] = objType
	}
	return allSupportedObjTypeMap, allSupportedObjTypes
}

// IsValidObjectType checks if the provided string is a valid objectType
func IsValidObjectType(objTypeToCheck string) bool {
	supportedObjTypes, _ := GetSupportedObjectTypes()
	_, ok := supportedObjTypes[ObjectType(objTypeToCheck)]
	return ok
}
