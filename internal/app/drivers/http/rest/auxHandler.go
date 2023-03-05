package rest

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"

	"openappsec.io/ctxutils"

	intel "openappsec.io/intelligencesdk/models"
	"openappsec.io/fog-msrv-waap-tuning-process/models"
	"openappsec.io/errors"
	"openappsec.io/httputils/responses"
	"openappsec.io/log"
)

const (
	attributeStatistics     intel.DataRequestField = intel.FieldAttributes + ".tuningStatistics"
	attributeSuggestions    intel.DataRequestField = intel.FieldAttributes + ".tuningSuggestions"
	attributeDecisions      intel.DataRequestField = intel.FieldAttributes + ".tuningDecisions"
	attributeExceptions     intel.DataRequestField = intel.FieldAttributes + ".assetExceptions"
	attributeCertStatus     intel.DataRequestField = intel.FieldAttributes + ".certificateStatus"
	attributeUpstreamStatus intel.DataRequestField = intel.FieldAttributes + ".upstreamStatus"
	attributeMgmtID         intel.DataRequestField = intel.FieldAttributes + ".mgmtId"

	confKeyIntelligenceBase     = "intelligence."
	confKeyIntelligenceAssetTTL = confKeyIntelligenceBase + "assetTTL"

	queryLogField  = "query"
	assetsLogField = "assets"

	assetsWildCard = "*"
)

// PostQuery handle post requests from intelligence
func (a *Adapter) PostQuery(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	log.WithContext(ctx).Info("Got query from intelligence")
	timeout := time.NewTimer(a.auxTimeout)
	defer timeout.Stop()
	responseCh := make(chan []byte)
	errCh := make(chan error)
	tenantID := ctxutils.ExtractString(ctx, ctxutils.ContextKeyTenantID)
	query, err := a.readIntelligenceBody(request)
	if err != nil {
		log.WithContext(ctx).Warnf(
			"Failed to read query body. Got error: %v",
			err.Error(),
		)
		if errors.IsClass(err, errors.ClassBadInput) {
			emptyResp := intel.QueryResponseAssets{
				Status: intel.QueryResultStatusDone,
				Assets: intel.Assets{},
			}
			emptyRespJSON, err := json.Marshal(emptyResp)
			if err != nil {
				httpReturnError(
					ctx,
					writer,
					http.StatusInternalServerError,
					request.URL.Path,
					"Failed to generate empty response on invalid read",
				)
			}

			responses.HTTPReturn(ctx, writer, http.StatusOK, emptyRespJSON, true)
			return
		}
		httpReturnError(
			ctx,
			writer,
			http.StatusBadRequest,
			request.URL.Path,
			"Failed to read query",
		)
		return
	}

	var tuningData []models.Attributes

	go func() {

		log.WithContext(ctx).Infof("Unmarshalling intelligence query. Body: %v", string(query))

		if cacheRes, ok := a.cache[tenantID][string(query)]; ok {
			log.WithContext(ctx).Infof("found response in cache")
			delete(a.cache[tenantID], string(query))
			responseCh <- cacheRes
			return
		}

		unmarshalledQuery, err := a.unmarshallIntelligenceQuery(query)
		if err != nil {
			log.WithContext(ctx).Warnf(
				"Failed to unmarshall intelligence query. Got error: %v",
				err,
			)
			err = errors.New(err.Error()).SetClass(errors.ClassBadInput)
			errCh <- err
			return
		}

		log.WithContext(ctx).Infof("intelligence query is: %v", unmarshalledQuery)

		assetID, err := a.parseIntelligenceQuery(tenantID, unmarshalledQuery)
		if err != nil {
			log.WithContext(ctx).Infof(
				"unable to parse intelligence query. Got error: %v",
				err,
			)
			emptyResp := intel.QueryResponseAssets{
				Status: intel.QueryResultStatusDone,
				Assets: intel.Assets{},
			}
			emptyRespJSON, err := json.Marshal(emptyResp)
			if err == nil {
				responseCh <- emptyRespJSON
				return
			}
			log.WithContext(ctx).Warnf("failed to marshal response(%T): %+v", emptyResp, emptyResp)
			errCh <- errors.New(err.Error()).SetClass(errors.ClassInternal)
			return
		}

		tuningData, err = a.tuningServiceV2.GetAll(ctx, tenantID, assetID)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to get tuning data, got error: %v", err)
			errCh <- err
			return
		}

		log.WithContext(ctx).Debugf("got %v tuning data", len(tuningData))

		response, err := a.buildResponse(ctx, tuningData)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to build response asset, got error: %v", err)
			errCh <- err
			return
		}

		result, err := json.Marshal(response)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to marshal response. Got error: %v", err)
			errCh <- err
			return
		}
		log.WithContext(ctx).Debugf("query response is ready")
		responseCh <- result
	}()
	select {
	case err := <-errCh:
		log.WithContext(ctx).Infof("got error while handling response: %v", err)
		if errors.IsClass(err, errors.ClassBadInput) {
			httpReturnError(
				ctx,
				writer,
				http.StatusBadRequest,
				request.URL.Path,
				http.StatusText(http.StatusBadRequest),
			)
		} else if errors.IsClass(err, errors.ClassNotFound) {
			httpReturnError(
				ctx,
				writer,
				http.StatusNotFound,
				request.URL.Path,
				http.StatusText(http.StatusNotFound),
			)
		} else {
			httpReturnError(
				ctx,
				writer,
				http.StatusInternalServerError,
				request.URL.Path,
				http.StatusText(http.StatusInternalServerError),
			)
		}
		return
	case res := <-responseCh:
		log.WithContext(ctx).Info("writing query HTTP response")
		logFields := log.Fields{
			queryLogField:  string(query),
			assetsLogField: string(res),
		}

		log.WithContextAndFields(ctx, logFields).Info("query finished successfully")
		responses.HTTPReturn(ctx, writer, http.StatusOK, res, true)
		return
	case <-timeout.C:
		log.WithContext(ctx).Infof("timeout(%v) exceeded returning empty response", a.auxTimeout)
		emptyResponse := intel.QueryResponseAssets{
			Assets:         intel.Assets{},
			Status:         intel.QueryResultStatusInProgress,
			TotalNumAssets: 0,
			Cursor:         "",
		}
		result, err := json.Marshal(emptyResponse)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to marshal response. Got error: %v", err)
			httpReturnError(
				ctx, writer, http.StatusInternalServerError, request.URL.Path,
				"failed to marshal response",
			)
			return
		}
		logFields := log.Fields{
			queryLogField:  string(query),
			assetsLogField: string(result),
		}
		log.WithContextAndFields(ctx, logFields).Info("query finished successfully, responding async")
		responses.HTTPReturn(ctx, writer, http.StatusOK, result, true)
	}
	select {
	case err = <-errCh:
		log.WithContext(ctx).Errorf("failed to handle query, err: %v", err)
		return
	case res := <-responseCh:
		log.WithContext(ctx).Infof("got response after timeout, cache response and notify on new data")
		if _, ok := a.cache[tenantID]; !ok {
			a.cache[tenantID] = map[string][]byte{}
		}
		a.cache[tenantID][string(query)] = res

		err = a.tuningServiceV2.AsyncResponse(ctx, tenantID, tuningData)
		if err != nil {
			log.WithContext(ctx).Errorf(
				"failed to update query(%v) response async, err: %v",
				string(query), err,
			)
			delete(a.cache[tenantID], string(query))
			return
		}
	}
}

func (a *Adapter) readIntelligenceBody(request *http.Request) ([]byte, error) {
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return []byte{}, errors.Wrap(err, "Failed to read request body.")
	}

	err = a.validJSONSchema(querySchemaName, body)
	if err != nil {
		return []byte{},
			errors.Wrap(err, "failed to validate query body with schema").SetClass(
				errors.ClassBadInput,
			)
	}

	return body, nil
}

func (a *Adapter) unmarshallIntelligenceQuery(queryBody []byte) (intel.Query, error) {
	var unmarshalledQuery intel.ReportedIntelQuery
	err := json.Unmarshal(queryBody, &unmarshalledQuery)
	if err != nil {
		return intel.Query{}, errors.Wrap(
			err,
			"Failed to unmarshall the intelligence body",
		)
	}

	return unmarshalledQuery.Query, nil
}

func (a *Adapter) parseIntelligenceQuery(tenantID string, intelligenceQuery intel.Query) (
	string,
	error,
) {
	switch intelligenceQuery.Operator {
	case intel.QueryOperatorAnd:
		if len(intelligenceQuery.Operands) < 2 {
			break
		}
		asset := ""
		var err error
		for _, operand := range intelligenceQuery.Operands {
			if asset != "" {
				break
			}
			asset, err = a.parseIntelligenceQuery(tenantID, operand)
		}
		if err == nil {
			return asset, nil
		}
	case intel.QueryOperatorNotEquals:
		fallthrough
	case intel.QueryOperatorNotEqualsLow:
		if intelligenceQuery.Key == "tenantId" {
			if intelligenceQuery.Value == tenantID {
				return "", errors.Errorf("query operand not satisfied: %v != %v", intelligenceQuery.Value, tenantID)
			}
		}
		if intelligenceQuery.Key == string(attributeMgmtID) &&
			intelligenceQuery.Value == assetsWildCard {
			return assetsWildCard, nil
		}
		if intelligenceQuery.Key == intel.FieldClass &&
			intelligenceQuery.Value == "true" {
			return assetsWildCard, nil
		}

	case intel.QueryOperatorEquals:
		fallthrough
	case intel.QueryOperatorEqualsLow:
		if intelligenceQuery.Key == string(attributeMgmtID) {
			return intelligenceQuery.Value.(string), nil
		}
	}
	return "", errors.Errorf("unable to extract asset id from %+v", intelligenceQuery).SetClass(errors.ClassNotFound)
}

func (a *Adapter) extractIDsFromQuery(intelligenceQuery intel.Query) ([]string, error) {
	switch intelligenceQuery.Key {
	case models.MainAttributeTuningID:
		return a.parseTuningID(intelligenceQuery)
	default:
		return []string{}, errors.Errorf(
			"Invalid main attribute key. Expecting %s,  Got: %v",
			models.MainAttributeTuningID,
			intelligenceQuery.Key,
		)
	}
}

func (a *Adapter) parseTuningID(query intel.Query) ([]string, error) {
	value, ok := query.Value.(string)
	if !ok {
		return []string{}, errors.Errorf(
			"Unsupported main attribute value within EQUALS operator, expected string. Got: %v+ ",
			reflect.ValueOf(value),
		)
	}
	splitKey := strings.Split(value, "#")
	if len(splitKey) != 2 {
		return []string{}, errors.Errorf(
			"failed to parse main attribute. Expected structure to be: <tenant_id>#<asset_id>. Got: %s",
			query.Value,
		)
	}

	return splitKey, nil
}

func (a *Adapter) buildResponse(
	ctx context.Context,
	data []models.Attributes,
) (intel.QueryResponseAssets, error) {
	log.WithContext(ctx).Debugf("build response from %+v", data)
	validAssetsCount := 0
	for _, singleAssetData := range data {
		if singleAssetData.ApplicationUrls != "" {
			validAssetsCount++
		}
	}
	assets := make([]intel.Asset, validAssetsCount)
	i := 0
	for _, singleAssetData := range data {
		if singleAssetData.ApplicationUrls == "" {
			log.WithContext(ctx).Warnf("application urls is missing from: %+v", singleAssetData)
			continue
		}
		responseAsset, err := a.buildResponseAsset(singleAssetData)
		if err != nil {
			return intel.QueryResponseAssets{}, errors.Wrap(err, "failed to build response")
		}

		assets[i] = responseAsset
		i++
	}

	return intel.QueryResponseAssets{
			Assets:         assets,
			Status:         intel.QueryResultStatusDone,
			TotalNumAssets: len(assets),
		},
		nil
}

func (a *Adapter) buildResponseAsset(
	data models.Attributes,
) (intel.Asset, error) {
	responseAsset := a.buildBaseAsset(data.ApplicationUrls)

	responseAsset.Name = data.Name
	responseAsset.AssetType = data.Type
	responseAsset.Family = data.Family

	err := responseAsset.AddDataRequestToAsset(attributeStatistics, data.Statistics)
	if err != nil {
		return intel.Asset{}, errors.Wrap(err, "failed to add tuning statistics to asset")
	}

	if data.TuningEvents == nil {
		data.TuningEvents = []models.TuneEvent{}
	}
	err = responseAsset.AddDataRequestToAsset(attributeSuggestions, data.TuningEvents)
	if err != nil {
		return intel.Asset{}, errors.Wrap(
			err,
			"failed to add tuning suggestions to asset",
		)
	}

	if data.TuningEventsDecided == nil {
		data.TuningEventsDecided = []models.TuneEvent{}
	}
	err = responseAsset.AddDataRequestToAsset(
		attributeDecisions,
		data.TuningEventsDecided,
	)
	if err != nil {
		return intel.Asset{}, errors.Wrap(err, "failed to add tuning decisions to asset")
	}

	err = responseAsset.AddDataRequestToAsset(
		attributeExceptions,
		data.AssetExceptions,
	)
	if err != nil {
		return intel.Asset{}, errors.Wrap(err, "failed to add exceptions data to asset")
	}

	err = responseAsset.AddDataRequestToAsset(
		attributeMgmtID,
		data.MgmtID,
	)
	if err != nil {
		return intel.Asset{}, errors.Wrap(err, "failed to add mgmt id to asset")
	}

	if len(data.CertInstallStatus) > 0 {
		certStatusArr := make([]models.CertInstallStatus, len(data.CertInstallStatus))
		i := 0
		for _, certStatus := range data.CertInstallStatus {
			certStatusArr[i] = certStatus
			i++
		}
		err = responseAsset.AddDataRequestToAsset(
			attributeCertStatus,
			certStatusArr,
		)
		if err != nil {
			return intel.Asset{}, errors.Wrap(err, "failed to add certificate installation status to asset")
		}
	}

	if len(data.UpstreamStatus) > 0 {
		upstreamStatusArr := make([]models.UpstreamHealthcheck, len(data.UpstreamStatus))
		j := 0
		for _, upstreamStatus := range data.UpstreamStatus {
			upstreamStatusArr[j] = models.UpstreamHealthcheck{
				Agent:   upstreamStatus.Agent,
				Status:  upstreamStatus.Status,
				Message: upstreamStatus.Message,
			}
			j++
		}
		err = responseAsset.AddDataRequestToAsset(
			attributeUpstreamStatus,
			upstreamStatusArr,
		)
		if err != nil {
			return intel.Asset{}, errors.Wrap(err, "failed to add upstream healthcheck status to asset")
		}
	}

	responseAsset.TTL = a.assetTTL

	return responseAsset, nil
}

func (a *Adapter) buildBaseAsset(applicationUrls string) intel.Asset {
	responseAsset := intel.Asset{
		SchemaVersion:          1,
		AssetType:              "WebApplication",
		AssetTypeSchemaVersion: 1,
		PermissionType:         "tenant",
		Class:                  "workload",
		Category:               "cloud",
		Family:                 "Web Application",
		Confidence:             900,
		Attributes:             map[string]interface{}{"excludeFromFacets": "true"},
	}

	responseAsset.MainAttributes = intel.MainAttributes{
		"applicationUrls": applicationUrls,
	}

	return responseAsset
}
