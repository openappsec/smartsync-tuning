package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"openappsec.io/ctxutils"

	"openappsec.io/intelligencesdk/models"

	"openappsec.io/errors"
	"openappsec.io/httputils/client"
	"openappsec.io/log"
)

const (
	// headers
	headerKeyTenantID             = "X-Tenant-Id"
	headerKeySourceID             = "X-Source-Id"
	headerKeyTraceID              = "X-Trace-Id"
	headerKeyCorrelationID        = "X-Correlation-Id"
	headerKeyCallingService       = "X-Calling-Service"
	headerKeyUpdateExistingAssets = "Update-Existing-Assets"
	headerKeyJWT                  = "authorization"
	headerValueJWTBearer          = "Bearer "
	headerKeyContentType          = "contentType"
	headerValueAppJSON            = "application/json"
	headerKeyUserAgent            = "user-agent"
	headerValueUserAgent          = "Infinity 2.0 (a683d9ce905d432)"

	// paths
	pathAPI           = "api"
	pathIntelligence  = "intelligence"
	pathAssets        = "assets"
	pathQuery         = "query"
	pathBulkQueries   = "queries"
	pathAsync         = "async"
	pathQueries       = "queries"
	pathSource        = "source"
	pathValidate      = "validate"
	pathTenants       = "tenants"
	pathInvalidation  = "invalidation"
	pathInvalRegister = "register"
	pathHealth        = "health"
)

// Adapter represents the intelligence SDK
type Adapter struct {
	HTTPClient       *http.Client
	IntelligenceHost string
}

// NewAdapter returns an intelligence SDK client
func NewAdapter(host string, timeout time.Duration) (*Adapter, error) {
	_, err := url.Parse(host)
	if err != nil {
		return &Adapter{}, err
	}

	a := &Adapter{
		HTTPClient:       client.NewTracerClient(timeout),
		IntelligenceHost: host,
	}

	return a, nil
}

func setReturnedErrorClass(statusCode int, err error) error {
	switch statusCode {
	case http.StatusBadRequest:
		return errors.New(err.Error()).SetClass(errors.ClassBadInput)
	case http.StatusNotFound:
		return errors.New(err.Error()).SetClass(errors.ClassNotFound)
	case http.StatusUnauthorized:
		return errors.New(err.Error()).SetClass(errors.ClassUnauthorized)
	default:
		return errors.New(err.Error())
	}

}

// PostAssets posts assets as the intelligence expects. error if couldn't send with status 200.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) PostAssets(ctx context.Context, identity models.Identity, updateExistingAssets bool, ass models.Assets) (models.ReportResponse, error) {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return models.ReportResponse{}, errors.Wrapf(err, "Could not parse intelligence host: %s", a.IntelligenceHost)
	}

	bodyBytes, err := json.Marshal(models.ReportedAssets{Assets: ass})
	if err != nil {
		return models.ReportResponse{}, errors.Wrapf(err, "Failed to marshal assets: (%+v)", ass)
	}

	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.ReportResponse{}, errors.Wrapf(err, "Failed to get API version from context")
	}
	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAssets)
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return models.ReportResponse{}, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s), body: (%s)", http.MethodPost, u.String(), string(bodyBytes))
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	req.Header.Add(headerKeyContentType, headerValueAppJSON)
	req.Header.Add(headerKeyUpdateExistingAssets, strconv.FormatBool(updateExistingAssets))

	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	if err := addIdentityHeaders(req, identity); err != nil {
		return models.ReportResponse{}, errors.Wrap(err, "Invalid request")
	}

	log.WithContext(ctx).Debugf("Adding assets via POST HTTP call to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return models.ReportResponse{}, errors.Wrapf(err, "Failed to send HTTP POST request to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response status: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return models.ReportResponse{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from POST request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}
		return models.ReportResponse{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from POST request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	if bodyErr != nil {
		return models.ReportResponse{}, errors.Wrapf(err, "Status code is: %d. Could not read body", res.StatusCode)
	}

	var rr models.ReportResponse
	if err := json.Unmarshal(resBody, &rr); err != nil {
		return models.ReportResponse{}, errors.Wrapf(err, "Response body: %s could not be converted to type query response", string(resBody))
	}

	return rr, nil
}

func createQueryString(query map[string]string, limit *int, offset *int, requestedAttributes []string, minConfidence *int, cursor *string) string {
	params := url.Values{}
	if query != nil {
		var b bytes.Buffer
		qLen := len(query)
		var i int
		for k, v := range query {
			i++
			b.WriteString(fmt.Sprintf("\"%s\":\"%s\"", k, v))
			if i < qLen {
				b.WriteString("+")
			}
		}
		params.Add("q", b.String())
	}

	if limit != nil {
		params.Add("limit", strconv.Itoa(*limit))
	}

	if offset != nil {
		params.Add("offset", strconv.Itoa(*offset))
	}

	if cursor != nil {
		params.Add("cursor", *cursor)
	}

	for _, k := range requestedAttributes {
		params.Add("requestedAttributes", k)
	}

	if minConfidence != nil {
		params.Add("minConfidence", strconv.Itoa(*minConfidence))
	}
	return params.Encode()
}

// SimpleQueryIntelAssets is a simple get assets query to the intelligence for api version v1.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) SimpleQueryIntelAssets(ctx context.Context, identity models.Identity, query map[string]string, limit *int, offset *int, requestedAttributes []string, minConfidence *int) (models.QueryResponse, error) {
	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.QueryResponse{}, errors.Wrapf(err, "Failed to get API version from context")
	}

	if apiV != models.APIV1 {
		return models.QueryResponse{}, errMsgUnsupportedCallForAPI("SimpleQueryAssetsIntel", apiV, []string{models.APIV1})
	}

	resBody, err := a.simpleQueryIntelAssetsExec(ctx, identity, apiV, query, limit, offset, requestedAttributes, minConfidence, nil)
	if err != nil {
		return models.QueryResponse{}, err
	}

	var qr models.QueryResponse
	if err := json.Unmarshal(resBody, &qr); err != nil {
		return models.QueryResponse{}, errors.Wrapf(err, "Response body: %s could not be converted to type query response", string(resBody))
	}

	return qr, nil
}

// SimpleQueryIntelAssetCollections is a simple get asset collections query to the intelligence for api version v2.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) SimpleQueryIntelAssetCollections(ctx context.Context, identity models.Identity, query map[string]string, limit *int, cursor *string, requestedAttributes []string, minConfidence *int) (
	models.QueryResponseAssetCollections, error) {
	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.QueryResponseAssetCollections{}, errors.Wrapf(err, "Failed to get API version from context")
	}

	if apiV != models.APIV2 {
		return models.QueryResponseAssetCollections{}, errMsgUnsupportedCallForAPI("SimpleQueryAssetsIntelV2", apiV, []string{models.APIV2})
	}

	resBody, err := a.simpleQueryIntelAssetsExec(ctx, identity, apiV, query, limit, nil, requestedAttributes, minConfidence, cursor)
	if err != nil {
		return models.QueryResponseAssetCollections{}, err
	}

	var qr models.QueryResponseAssetCollections
	if err := json.Unmarshal(resBody, &qr); err != nil {
		return models.QueryResponseAssetCollections{}, errors.Wrapf(err, "Response body: %s could not be converted to type QueryResponseAssetCollections", string(resBody))
	}

	return qr, nil
}

func (a *Adapter) simpleQueryIntelAssetsExec(ctx context.Context, identity models.Identity, apiV string, query map[string]string, limit *int, offset *int, requestedAttributes []string, minConfidence *int, cursor *string) ([]byte, error) {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return nil, errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAssets)
	u.RawQuery = createQueryString(query, limit, offset, requestedAttributes, minConfidence, cursor)
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodGet, u.String())
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err = addIdentityHeaders(req, identity); err != nil {
		return nil, errors.Wrap(err, "Invalid request")
	}
	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("querying assets via GET HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to send HTTP GET request to: (%s)", u.String())
	}
	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response status: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return nil, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Get request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}
		return nil, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Get request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	if bodyErr != nil {
		return nil, errors.Wrapf(err, "Status code is: %d. Could not read body", res.StatusCode)
	}

	return resBody, nil
}

// QueryIntelAssets queries the intelligence for api version v1.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) QueryIntelAssets(ctx context.Context, identity models.Identity, query models.ReportedIntelQuery) (models.QueryResponse, error) {
	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.QueryResponse{}, errors.Wrapf(err, "Failed to get API version from context")
	}

	if apiV != models.APIV1 {
		return models.QueryResponse{}, errMsgUnsupportedCallForAPI("QueryAssetsIntel", apiV, []string{models.APIV1})
	}

	bodyBytes, err := json.Marshal(query)
	if err != nil {
		return models.QueryResponse{}, errors.Wrapf(err, "Failed to marshal query: (%+v)", query)
	}

	resBody, err := a.queryAssetsIntelExec(ctx, identity, bodyBytes, apiV)
	if err != nil {
		return models.QueryResponse{}, err
	}

	var qr models.QueryResponse
	if err := json.Unmarshal(resBody, &qr); err != nil {
		return models.QueryResponse{}, errors.Wrapf(err, "Response body: %s could not be converted to type query response", string(resBody))
	}

	return qr, nil
}

// QueryIntelAssetCollections queries the intelligence for asset collections for api version v2.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) QueryIntelAssetCollections(ctx context.Context, identity models.Identity, query models.IntelQueryV2) (models.QueryResponseAssetCollections, error) {
	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.QueryResponseAssetCollections{}, errors.Wrapf(err, "Failed to get API version from context")
	}

	if apiV != models.APIV2 {
		return models.QueryResponseAssetCollections{}, errMsgUnsupportedCallForAPI("QueryAssetsIntelV2", apiV, []string{models.APIV2})
	}

	bodyBytes, err := json.Marshal(query)
	if err != nil {
		return models.QueryResponseAssetCollections{}, errors.Wrapf(err, "Failed to marshal query: (%+v)", query)
	}

	resBody, err := a.queryAssetsIntelExec(ctx, identity, bodyBytes, apiV)
	if err != nil {
		return models.QueryResponseAssetCollections{}, err
	}

	var qr models.QueryResponseAssetCollections
	if err := json.Unmarshal(resBody, &qr); err != nil {
		return models.QueryResponseAssetCollections{}, errors.Wrapf(err, "Response body: %s could not be converted to type QueryResponseAssetCollections", string(resBody))
	}

	return qr, nil
}

// QueryIntelAssetsV2 queries the intelligence for assets for api version v2.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) QueryIntelAssetsV2(ctx context.Context, identity models.Identity, query models.IntelQueryV2) (models.QueryResponseAssets, error) {
	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.QueryResponseAssets{}, errors.Wrapf(err, "Failed to get API version from context")
	}

	if apiV != models.APIV2 {
		return models.QueryResponseAssets{}, errMsgUnsupportedCallForAPI("QueryAssetsIntelV2", apiV, []string{models.APIV2})
	}

	query.ResponseType = models.QueryResponseTypeAssets

	bodyBytes, err := json.Marshal(query)
	if err != nil {
		return models.QueryResponseAssets{}, errors.Wrapf(err, "Failed to marshal query: (%+v)", query)
	}

	resBody, err := a.queryAssetsIntelExec(ctx, identity, bodyBytes, apiV)
	if err != nil {
		return models.QueryResponseAssets{}, err
	}

	var qr models.QueryResponseAssets
	if err := json.Unmarshal(resBody, &qr); err != nil {
		return models.QueryResponseAssets{}, errors.Wrapf(err, "Response body: %s could not be converted to type QueryResponseAssets", string(resBody))
	}

	return qr, nil
}

func (a *Adapter) queryAssetsIntelExec(ctx context.Context, identity models.Identity, bodyBytes []byte, apiV string) ([]byte, error) {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not parse intelligence host: %s", a.IntelligenceHost)
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAssets, pathQuery)
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s), body: (%s)", http.MethodPost, u.String(), string(bodyBytes))
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	req.Header.Add(headerKeyContentType, headerValueAppJSON)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return nil, errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("querying assets via POST HTTP call to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to send HTTP POST request to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response status: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return nil, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}
		return nil, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	if bodyErr != nil {
		return nil, errors.Wrapf(err, "Status code is: %d. Could not read body", res.StatusCode)
	}

	return resBody, nil
}

// BulkQueries queries the intelligence for asset collections for api version v2 with bulk queries.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) BulkQueries(ctx context.Context, identity models.Identity, queries models.ReportedBulkQueries) (models.BulkQueriesRes, error) {
	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.BulkQueriesRes{}, errors.Wrapf(err, "Failed to get API version from context")
	}

	if apiV != models.APIV2 {
		return models.BulkQueriesRes{}, errMsgUnsupportedCallForAPI("BulkQueries", apiV, []string{models.APIV2})
	}

	bodyBytes, err := json.Marshal(queries)
	if err != nil {
		return models.BulkQueriesRes{}, errors.Wrapf(err, "Failed to marshal bulk queries: (%+v)", queries)
	}

	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return models.BulkQueriesRes{}, errors.Wrapf(err, "Could not parse intelligence host: %s", a.IntelligenceHost)
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAssets, pathBulkQueries)
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return models.BulkQueriesRes{}, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s), body: (%s)", http.MethodPost, u.String(), string(bodyBytes))
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	req.Header.Add(headerKeyContentType, headerValueAppJSON)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err = addIdentityHeaders(req, identity); err != nil {
		return models.BulkQueriesRes{}, errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("querying assets via POST HTTP call to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return models.BulkQueriesRes{}, errors.Wrapf(err, "Failed to send HTTP POST request to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response status: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return models.BulkQueriesRes{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}
		return models.BulkQueriesRes{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	if bodyErr != nil {
		return models.BulkQueriesRes{}, errors.Wrapf(err, "Status code is: %d. Could not read body", res.StatusCode)
	}

	var qr models.BulkQueriesRes
	if err := json.Unmarshal(resBody, &qr); err != nil {
		return models.BulkQueriesRes{}, errors.Wrapf(err, "Response body: %s could not be converted to type BulkQueriesRes", string(resBody))
	}

	return qr, nil
}

// GetAsset get an asset in the intelligence. error if couldn't send with status 200.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) GetAsset(ctx context.Context, identity models.Identity, assetID string) (models.Asset, error) {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return models.Asset{}, errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.Asset{}, errors.Wrapf(err, "Failed to get API version from context")
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAssets, assetID)
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return models.Asset{}, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodDelete, u.String())
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return models.Asset{}, errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("Getting asset via GET HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return models.Asset{}, errors.Wrapf(err, "Failed to send HTTP GET request to: (%s)", u.String())
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return models.Asset{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from GET asset request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}
		return models.Asset{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from GET asset request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	if bodyErr != nil {
		return models.Asset{}, errors.Wrapf(bodyErr, "Status code is: %d. Could not read body", res.StatusCode)
	}

	var ar models.Asset
	if err := json.Unmarshal(resBody, &ar); err != nil {
		return models.Asset{}, errors.Wrapf(err, "Response body: %s could not be converted to type asset", string(resBody))
	}

	return ar, nil
}

// PutAsset put an asset in the intelligence. error if couldn't send with status 200.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) PutAsset(ctx context.Context, identity models.Identity, assetID string, asset models.Asset) error {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	bodyBytes, err := json.Marshal(asset)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal assets: (%+v)", asset)
	}

	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed to get API version from context")
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAssets, assetID)
	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s), body: (%s)", http.MethodDelete, u.String(), string(bodyBytes))
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	req.Header.Add(headerKeyContentType, headerValueAppJSON)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("Getting asset via PUT HTTP call to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "Failed to send HTTP PUT request to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response: %s", res.Status)
	if res.StatusCode != http.StatusOK {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from PUT asset request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}
		return setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from PUT asset request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	return nil
}

// PatchAsset patch an asset in the intelligence. error if couldn't send with status 200.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) PatchAsset(ctx context.Context, identity models.Identity, assetID string, updateAsset models.AssetUpdate) error {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	bodyBytes, err := json.Marshal(updateAsset)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal assets: (%+v)", updateAsset)
	}

	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return errors.Wrap(err, "Failed to get API version from context")
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAssets, assetID)
	req, err := http.NewRequest(http.MethodPatch, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s), body: (%s)", http.MethodDelete, u.String(), string(bodyBytes))
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	req.Header.Add(headerKeyContentType, headerValueAppJSON)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("Getting asset via PATCH HTTP call to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "Failed to send HTTP PATCH request to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response: %s", res.Status)
	if res.StatusCode != http.StatusOK {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from PATCH asset request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}

		return setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from PATCH asset request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	return nil
}

// DeleteAsset deletes an asset in the intelligence. error if couldn't send with status 200.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) DeleteAsset(ctx context.Context, identity models.Identity, assetID string) error {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return errors.Wrap(err, "Failed to get API version from context")
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAssets, assetID)
	req, err := http.NewRequest(http.MethodDelete, u.String(), nil)
	if err != nil {
		return errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodDelete, u.String())
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("Deleting asset via DELETE HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "Failed to send HTTP DELETE request to: (%s)", u.String())
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response: %s", res.Status)
	if res.StatusCode != http.StatusOK {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from DELETE request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}

		return setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from DELETE request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	return nil
}

// RegisterExternalSource registers an external source to the intelligence. error if couldn't send with status 200.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) RegisterExternalSource(ctx context.Context, identity models.Identity, extSrcReg models.ExternalSourceReg) (string, error) {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return "", errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	bodyBytes, err := json.Marshal(extSrcReg)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to marshal external source registration body: (%+v)", extSrcReg)
	}

	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return "", errors.Wrap(err, "Failed to get API version from context")
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathSource)
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return "", errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodPost, u.String())
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return "", errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("Registering external source to intelligence via POST HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to send HTTP POST request to: (%s)", u.String())
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return "", setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from register external source request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}

		return "", setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from register external source request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	if bodyErr != nil {
		return "", errors.Wrapf(bodyErr, "Status code is: %d. Could not read body", res.StatusCode)
	}

	return string(resBody), nil
}

// AsyncGetQueriesAndInvalidation is a call made by child intelligence source to GET published queries and invalidation records by parent intelligence source
func (a *Adapter) AsyncGetQueriesAndInvalidation(ctx context.Context, identity models.Identity) (models.AsyncChildQueryAndInvalidationRequests, error) {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return models.AsyncChildQueryAndInvalidationRequests{}, errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.AsyncChildQueryAndInvalidationRequests{}, errors.Wrap(err, "Failed to get API version from context")
	}

	if apiV == models.APIV1 {
		return models.AsyncChildQueryAndInvalidationRequests{}, errMsgUnsupportedCallForAPI("AsyncGetQueriesAndInvalidation", apiV, []string{models.APIV2})
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAsync, pathQueries)

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return models.AsyncChildQueryAndInvalidationRequests{}, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodGet, u.String())
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return models.AsyncChildQueryAndInvalidationRequests{}, errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("Querying for async child queries and invalidation records via GET HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return models.AsyncChildQueryAndInvalidationRequests{}, errors.Wrapf(err, "Failed to send HTTP GET request to: (%s)", u.String())
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response status: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return models.AsyncChildQueryAndInvalidationRequests{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Get request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}

		return models.AsyncChildQueryAndInvalidationRequests{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Get request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	if bodyErr != nil {
		return models.AsyncChildQueryAndInvalidationRequests{}, errors.Wrapf(err, "Status code is: %d. Could not read body", res.StatusCode)
	}

	var qr models.AsyncChildQueryAndInvalidationRequests
	if err := json.Unmarshal(resBody, &qr); err != nil {
		return models.AsyncChildQueryAndInvalidationRequests{}, errors.Wrapf(err, "Response body: %s could not be converted to type query and invalidation response", string(resBody))
	}

	return qr, nil
}

// AsyncPostQueries is a call made by child intelligence source to post queries results of published queries
func (a *Adapter) AsyncPostQueries(ctx context.Context, identity models.Identity, queries models.ReportedAsyncChildQueriesResult) (models.AsyncParentQueriesStatus, error) {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return models.AsyncParentQueriesStatus{}, errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.AsyncParentQueriesStatus{}, errors.Wrap(err, "Failed to get API version from context")
	}

	if apiV == models.APIV1 {
		return models.AsyncParentQueriesStatus{}, errMsgUnsupportedCallForAPI("AsyncPostQueries", apiV, []string{models.APIV2})
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAsync, pathAssets)

	bodyBytes, err := json.Marshal(queries)
	if err != nil {
		return models.AsyncParentQueriesStatus{}, errors.Wrapf(err, "Failed to marshal queries responses: (%+v)", queries)
	}

	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return models.AsyncParentQueriesStatus{}, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodPost, u.String())
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return models.AsyncParentQueriesStatus{}, errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("POSTing queries responses via POST HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return models.AsyncParentQueriesStatus{}, errors.Wrapf(err, "Failed to send HTTP POST request to: (%s)", u.String())
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response status: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return models.AsyncParentQueriesStatus{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}

		return models.AsyncParentQueriesStatus{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	var qr models.AsyncParentQueriesStatus
	if err := json.Unmarshal(resBody, &qr); err != nil {
		return models.AsyncParentQueriesStatus{}, errors.Wrapf(err, "Response body: %s could not be converted to type async query response", string(resBody))
	}

	return qr, nil
}

// AsyncInvalidation is a call made by child intelligence source to post invalidation and get relevant assets
func (a *Adapter) AsyncInvalidation(ctx context.Context, identity models.Identity, invalidations models.AsyncInvalidations) (models.Assets, error) {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return models.Assets{}, errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.Assets{}, errors.Wrap(err, "Failed to get API version from context")
	}

	if apiV != models.APIV2 {
		return models.Assets{}, errMsgUnsupportedCallForAPI("AsyncInvalidation", apiV, []string{models.APIV2})
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAsync, pathInvalidation)

	bodyBytes, err := json.Marshal(invalidations)
	if err != nil {
		return models.Assets{}, errors.Wrapf(err, "Failed to marshal async invalidations: (%+v)", invalidations)
	}

	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return models.Assets{}, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodPost, u.String())
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return models.Assets{}, errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("POSTing async invalidations via POST HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return models.Assets{}, errors.Wrapf(err, "Failed to send HTTP POST request to: (%s)", u.String())
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response status: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return models.Assets{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}

		return models.Assets{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	var assetsForInval models.Assets
	if err := json.Unmarshal(resBody, &assetsForInval); err != nil {
		return models.Assets{}, errors.Wrapf(err, "Response body: %s could not be converted to type assets", string(resBody))
	}

	log.WithContext(ctx).Debugf("Assets for invalidation returned from parent: %v", assetsForInval)
	return assetsForInval, nil
}

// ValidateAssets validates the assets listed in reportedAssets.
func (a *Adapter) ValidateAssets(ctx context.Context, reportedAssets models.ReportedAssets, identity models.Identity) (models.AssetValidationResponse, error) {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return models.AssetValidationResponse{}, errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	bodyBytes, err := json.Marshal(reportedAssets)
	if err != nil {
		return models.AssetValidationResponse{}, errors.Wrapf(err, "Failed to marshal reportedAssets body: (%+v)", reportedAssets)
	}

	apiV := ctxutils.ExtractString(ctx, ctxutils.ContextKeyAPIVersion)
	if apiV == models.APILegacy {
		u.Path = path.Join(u.Path, pathIntelligence, pathValidate)
		log.WithContext(ctx).Debug("Using legacy API version")
	} else if apiV == models.APIV1 || apiV == models.APIV2 {
		u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathValidate)
	} else {
		return models.AssetValidationResponse{}, errors.Errorf("API version passed through context (%s) is unsupported.", apiV)
	}

	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return models.AssetValidationResponse{}, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodPost, u.String())
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return models.AssetValidationResponse{}, errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("POSTing asset for validation via POST HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return models.AssetValidationResponse{}, errors.Wrapf(err, "Failed to send HTTP POST request to: (%s)", u.String())
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response status: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return models.AssetValidationResponse{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}

		return models.AssetValidationResponse{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	var vr models.AssetValidationResponse
	if err := json.Unmarshal(resBody, &vr); err != nil {
		return models.AssetValidationResponse{}, errors.Wrapf(err, "Response body: %s could not be converted to type asset validation response", string(resBody))
	}

	return vr, nil
}

// ValidateQueries validates the queries listed.
func (a *Adapter) ValidateQueries(ctx context.Context, queries models.ValidateQueriesRequest, identity models.Identity) (models.QueryValidationResponse, error) {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return models.QueryValidationResponse{}, errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	bodyBytes, err := json.Marshal(queries)
	if err != nil {
		return models.QueryValidationResponse{}, errors.Wrapf(err, "Failed to marshal queries body: (%+v)", queries)
	}

	apiV := ctxutils.ExtractString(ctx, ctxutils.ContextKeyAPIVersion)
	if apiV != models.APIV2 {
		return models.QueryValidationResponse{}, errors.Errorf("API version passed through context (%s) is unsupported.", apiV)
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathValidate+"/"+pathQuery)

	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return models.QueryValidationResponse{}, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodPost, u.String())
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return models.QueryValidationResponse{}, errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("POSTing queries for validation via POST HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return models.QueryValidationResponse{}, errors.Wrapf(err, "Failed to send HTTP POST request to: (%s)", u.String())
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response status: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return models.QueryValidationResponse{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}

		return models.QueryValidationResponse{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	var vr models.QueryValidationResponse
	if err := json.Unmarshal(resBody, &vr); err != nil {
		return models.QueryValidationResponse{}, errors.Wrapf(err, "Response body: %s could not be converted to type query validation response", string(resBody))
	}

	return vr, nil
}

// Invalidation sends invalidations request to the intelligence for api version v2.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) Invalidation(ctx context.Context, identity models.Identity, invalidations models.ReportedInvalidations) error {
	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed to get API version from context")
	}

	if apiV != models.APIV2 {
		return errMsgUnsupportedCallForAPI("Invalidation", apiV, []string{models.APIV2})
	}

	bodyBytes, err := json.Marshal(invalidations)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal invalidations request: (%+v)", invalidations)
	}

	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return errors.Wrapf(err, "Could not parse intelligence host: %s", a.IntelligenceHost)
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathInvalidation)
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s), body: (%s)", http.MethodPost, u.String(), string(bodyBytes))
	}

	req.Header.Add(headerKeyUserAgent, headerValueUserAgent)
	req.Header.Add(headerKeyContentType, headerValueAppJSON)
	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err = addIdentityHeaders(req, identity); err != nil {
		return errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("Sending invalidation request via POST HTTP call to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "Failed to send HTTP POST request to: (%s), with body: (%s)", u.String(), string(bodyBytes))
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response status: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}

		return setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from Post request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	return nil
}

// RegisterForInvalidation sends external source invalidation registration request to the intelligence for api version v2.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) RegisterForInvalidation(ctx context.Context, identity models.Identity, invalReg models.InvalidationReg) error {
	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return errors.Wrap(err, "Failed to get API version from context")
	}

	if apiV != models.APIV2 {
		return errMsgUnsupportedCallForAPI("RegisterForInvalidation", apiV, []string{models.APIV2})
	}

	bodyBytes, err := json.Marshal(invalReg)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal external source invalidation registration body: (%+v)", invalReg)
	}

	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathInvalidation, pathInvalRegister)
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodPost, u.String())
	}

	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err := addIdentityHeaders(req, identity); err != nil {
		return errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("Registering external source to intelligence invalidations via POST HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "Failed to send HTTP POST request to: (%s)", u.String())
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from register external source request to intelligence invalidations (%d). Could not get body for logging", res.StatusCode))
		}

		return setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from register external source request to intelligence invalidations (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	return nil
}

// AsyncValidateTenants sends validate tenants request to the intelligence for api version v2.
// If given a non-empty JWT the sourceID and tenantID header will be ignored in favor of the JWT.
func (a *Adapter) AsyncValidateTenants(ctx context.Context, identity models.Identity, reportedMultiTenants models.ReportedMultiTenants) (models.TenantsMap, error) {
	apiV, err := models.GetAPIVersionFromContext(ctx)
	if err != nil {
		return models.TenantsMap{}, errors.Wrap(err, "Failed to get API version from context")
	}

	if apiV != models.APIV2 {
		return models.TenantsMap{}, errMsgUnsupportedCallForAPI("AsyncValidateTenants", apiV, []string{models.APIV2})
	}

	bodyBytes, err := json.Marshal(reportedMultiTenants)
	if err != nil {
		return models.TenantsMap{}, errors.Wrapf(err, "Failed to marshal tenants to validate body: (%+v)", reportedMultiTenants)
	}

	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return models.TenantsMap{}, errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	u.Path = path.Join(u.Path, pathAPI, apiV, pathIntelligence, pathAsync, pathValidate, pathTenants)
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return models.TenantsMap{}, errors.Wrapf(err, "Failed to create request for intelligence with method: (%s), url: (%s)", http.MethodPost, u.String())
	}

	if callingServiceName := ctxutils.ExtractString(ctx, ctxutils.ContextKeyCallingService); callingServiceName != "" {
		req.Header.Add(headerKeyCallingService, callingServiceName)
	}

	if err = addIdentityHeaders(req, identity); err != nil {
		return models.TenantsMap{}, errors.Wrap(err, "Invalid request")
	}

	setCorrelationIDTraceIDHeader(ctx, req)

	log.WithContext(ctx).Debugf("Validate tenants via POST HTTP call to: (%s)", u.String())
	res, err := a.HTTPClient.Do(req)
	if err != nil {
		return models.TenantsMap{}, errors.Wrapf(err, "Failed to send HTTP POST request to: (%s)", u.String())
	}

	defer res.Body.Close()

	log.WithContext(ctx).Debugf("Response: %s", res.Status)
	resBody, bodyErr := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		if bodyErr != nil {
			return models.TenantsMap{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from validate tenants request to intelligence (%d). Could not get body for logging", res.StatusCode))
		}

		return models.TenantsMap{}, setReturnedErrorClass(res.StatusCode, errors.Errorf("Non-OK HTTP code returned from validate tenants request to intelligence (%d) with body: (%s)", res.StatusCode, string(resBody)))
	}

	var vt models.TenantsMap
	if err := json.Unmarshal(resBody, &vt); err != nil {
		return models.TenantsMap{}, errors.Wrapf(err, "Response body: %s could not be converted to type TenantsMap response", string(resBody))
	}

	return vt, nil
}

// Live is the api to the lively test
func (a *Adapter) Live(ctx context.Context) error {
	return a.health(ctx, "live")
}

// Ready is the api to the lively test
func (a *Adapter) Ready(ctx context.Context) error {
	return a.health(ctx, "ready")
}

func (a *Adapter) health(ctx context.Context, check string) error {
	u, err := url.Parse(a.IntelligenceHost)
	if err != nil {
		return errors.Wrapf(err, "could not parse intelligence host: %s", a.IntelligenceHost)
	}

	u.Path = path.Join(u.Path, pathHealth, check)
	res, err := http.Get(u.String())
	if err != nil {
		return errors.Wrapf(err, "could not check intelligence %s status method: (%s), url: (%s)", check, http.MethodGet, u.String())
	}

	log.WithContext(ctx).Infof("Response: %s", res.Status)
	if res.StatusCode != http.StatusOK {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return errors.Errorf("Non-OK HTTP code returned from %s status request to intelligence (%d). Could not get body for logging", check, res.StatusCode)
		}
		return errors.Errorf("Non-OK HTTP code returned from %s status request to intelligence (%d) with body: (%s)", check, res.StatusCode, string(resBody))
	}

	return nil
}

// add jwt header if exists, otherwise add tenantId and sourceId headers
func addIdentityHeaders(req *http.Request, identity models.Identity) error {
	if identity.Jwt != "" {
		req.Header.Add(headerKeyJWT, headerValueJWTBearer+identity.Jwt)
	} else if identity.TenantID != "" && identity.SourceID != "" {
		req.Header.Add(headerKeyTenantID, identity.TenantID)
		req.Header.Add(headerKeySourceID, identity.SourceID)
	} else {
		return errors.New("Missing identity info, JWT or TenantID and SourceID are required").SetClass(errors.ClassBadInput)
	}

	return nil
}

func setCorrelationIDTraceIDHeader(ctx context.Context, req *http.Request) {
	req.Header.Set(headerKeyTraceID, ctxutils.ExtractString(ctx, ctxutils.ContextKeyEventTraceID))
	req.Header.Set(headerKeyCorrelationID, ctxutils.ExtractString(ctx, ctxutils.ContextKeyEventTraceID))
}

func errMsgUnsupportedCallForAPI(funcName, apiV string, supportedVersions []string) error {
	return errors.Errorf(
		"Call to %s is not supported for API version %s. Please insert to the context a supported API version [%v]", funcName, apiV, supportedVersions).SetClass(errors.ClassBadInput)

}
