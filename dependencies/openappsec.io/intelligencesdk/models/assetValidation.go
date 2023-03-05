package models

const (
	// AssetField is the name of the key in a valid reported assets request body
	AssetField = "assets"
	// QueriesField is the name of the key in validate queries request's body
	QueriesField = "queries"
	// InternalServerErrorMsg is the error message of AssetValidationError when StatusCode is 500
	InternalServerErrorMsg = "Internal server error"
)

// AssetValidationError describes the error found while validating an asset located in an array of assets at the specified index
type AssetValidationError struct {
	Index      int    `json:"reportedAssetAtIndex" bson:"reportedAssetAtIndex"`
	StatusCode int    `json:"statusCode" bson:"statusCode"`
	Error      string `json:"errorMessage" bson:"errorMessage"`
}

// AssetValidationErrors is an array of AssetValidationError
type AssetValidationErrors []AssetValidationError

// AssetValidationResponse is the response struct for validate assets request
type AssetValidationResponse struct {
	ErrorsFound AssetValidationErrors `json:"assetValidationErrors" bson:"assetValidationErrors"`
}

// AssetValidationRequest is the request body made by the Intelligence to the ExternalSource in case the ExternalSource reported invalid assets
type AssetValidationRequest struct {
	ErrorsFound AssetValidationErrors `json:"assetValidationErrors" bson:"assetValidationErrors"`
	TraceID     string                `json:"traceId" bson:"traceId"`
}

// ValidateQueriesRequest is the request body of the queries' validation API
type ValidateQueriesRequest struct {
	Queries Queries `json:"queries"`
}

// QueryValidationResponse is the response struct for validate queries request
type QueryValidationResponse struct {
	Errors BulkErrors `json:"errors"`
}
