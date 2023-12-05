package models

import "openappsec.io/log"

// field names for logs
const (
	LogFieldRawAssetID                    = "rawAssetId"
	LogFieldAsset                         = "asset"
	LogFieldAssets                        = "assets"
	LogFieldTruncatedAssets               = "truncatedAssets"
	LogFieldUpdates                       = "updates"
	LogFieldRawQuery                      = "rawQuery"
	LogFieldQuery                         = "query"
	LogFieldQueryCorrelationID            = "queryCorrelationId"
	LogFieldQueryIPvAddress               = "queryIpvAddress"
	LogFieldSourceName                    = "sourceName"
	LogFieldRequestBody                   = log.FieldNameRequestBody
	LogFieldAccessType                    = "accessType"
	LogFieldExtSrcID                      = "extSrcID"
	LogFieldAsyncParentGetQueriesAndInval = "asyncParentGetQueriesAndInvalidation"
	LogFieldAsyncChildQueriesResult       = "asyncChildQueriesResult"
	LogFieldExternalSources               = "externalSources"
	LogFieldExternalRequest               = "externalRequest"
	LogFieldQueryType                     = "queryType"
	LogFieldQueryTime                     = "queryTime"
	LogFieldNumWorkerRetries              = "workerRetryNumberToGetQueryToDone"
	LogFieldRequestingTenantID            = "requestingTenantID"
	LogFieldAppStopped                    = "appStopped"
	LogFieldRuntimeNumGoroutine           = "runtimeNumGoroutine"
	LogFieldRuntimeNumCgoCall             = "runtimeNumCgoCall"
	LogFieldRuntimeNumCPU                 = "runtimeNumCPU"
	LogFieldRuntimeGOMAXPROCS             = "runtimeGOMAXPROCS"
	LogFieldInvalidationsNum              = "invalidationsNum"
	LogFieldInvalidations                 = "invalidations"
	LogFieldInvalidationClass             = "invalidationClass"
	LogFieldInvalidationCategory          = "invalidationCategory"
	LogFieldInvalidationFamily            = "invalidationFamily"
	LogFieldInvalidationGroup             = "invalidationGroup"
	LogFieldInvalidationOrder             = "invalidationOrder"
	LogFieldInvalidationKind              = "invalidationKind"
	LogFieldInvalidationMainAttributes    = "invalidationMainAttributes"
	LogFieldInvalidationObjectType        = "invalidationObjectType"
	LogFieldLogTrail                      = "logTrail"
	LogFieldLogTrailTimeInterval          = "logTrailTimeIntervalInMilliseconds"
	LogFieldNumAssetsFound                = "numAssetsFoundInDB"
	LogFieldNumAssetCollection            = "numOfAssetCollections"
	LogFieldCleanupTime                   = "cleanupTime"
	LogFieldCleanupDeletedKeysPerSecond   = "deletedKeysPerSecond"
	LogFieldNumberOfCleanedKeys           = "totalMissingKeysFoundInKeysSets"
)