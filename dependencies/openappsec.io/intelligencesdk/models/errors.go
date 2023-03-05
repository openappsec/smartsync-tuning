package models

// HTTPResError describes the error returned to the http response
type HTTPResError struct {
	StatusCode   int    `json:"statusCode"   bson:"statusCode"`
	ErrorMessage string `json:"errorMessage" bson:"errorMessage"`
}
