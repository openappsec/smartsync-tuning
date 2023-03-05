package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"openappsec.io/fog-msrv-waap-tuning-process/models"
	"openappsec.io/errors"
	"openappsec.io/httputils/client"
	"openappsec.io/log"
)

const (
	confKeyManagement          = "management"
	confKeyManagementPolicy    = confKeyManagement + ".policy"
	confKeyManagementPolicyURL = confKeyManagementPolicy + ".baseUrl"
	confKeyManagementAssets    = confKeyManagement + ".assets"
	confKeyManagementAssetsURL = confKeyManagementAssets + ".baseUrl"

	traceClientTimeout = 2 * time.Minute

	parameterHiddenNamePrefix = "$$$_tuningService_"
	parameterNamePrefix       = "tuningService_"

	matchSource    = "sourceidentifier"
	matchSourceIP  = "sourceip"
	matchURL       = "url"
	matchParamName = "paramname"
	matchParamVal  = "paramvalue"

	attributeType = "$type"
)

type mgmtOverrides struct {
	Behavior []map[string]string `json:"behavior"`
	Match    map[string]string   `json:"match"`
}

type mgmtOverrideParameter struct {
	Name      string          `json:"name"`
	Comment   string          `json:"comment"`
	ParamType string          `json:"$parameterType"`
	ID        string          `json:"id"`
	Overrides []mgmtOverrides `json:"overrides"`
}

type mgmtParameter struct {
	Name      string        `json:"name"`
	ParamType string        `json:"$parameterType"`
	ID        string        `json:"id"`
	Overrides []interface{} `json:"overrides"`
}

type mgmtGetParametersResponse struct {
	Total int             `json:"total"`
	Rows  []mgmtParameter `json:"rows"`
}

// Configuration used to get the configuration of the management hosts
type Configuration interface {
	GetString(key string) (string, error)
}

// stores the hidden and visible MGMT parameters id.
type parameterIDs struct {
	hidden  string
	visible string
}

// Adapter for MGMT rest API
type Adapter struct {
	conf       Configuration
	policyURL  string
	assetURL   string
	HTTPClient *http.Client
	parameters map[string]map[string]parameterIDs
}

// NewAdapter creates new adapter
func NewAdapter(c Configuration) (*Adapter, error) {
	a := &Adapter{conf: c, parameters: make(map[string]map[string]parameterIDs)}
	if err := a.initialize(); err != nil {
		return &Adapter{}, errors.Wrap(err, "failed to initialize MGMT rest adapter")
	}
	return a, nil
}

// initialize the adapter
func (a *Adapter) initialize() error {
	baseURL, err := a.conf.GetString(confKeyManagementPolicyURL)
	if err != nil {
		return errors.Wrapf(err, "failed to get mgmt policy baseURL from %v", confKeyManagementPolicyURL)
	}
	if _, err = url.Parse(baseURL); err != nil {
		return err
	}
	a.policyURL = baseURL

	baseURL, err = a.conf.GetString(confKeyManagementAssetsURL)
	if err != nil {
		return errors.Wrapf(err, "failed to get mgmt assets baseURL from %v", confKeyManagementAssetsURL)
	}
	if _, err = url.Parse(baseURL); err != nil {
		return err
	}
	a.assetURL = baseURL

	a.HTTPClient = client.NewTracerClient(traceClientTimeout)
	return nil
}

func (a *Adapter) httpGetRequest(host string, URI string, uQuery string) ([]byte, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, URI)

	u.RawQuery = url.QueryEscape(uQuery)

	resp, err := a.HTTPClient.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get from %v", u.String())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("get %v failed, status: %v", u.String(), resp.Status)
	}

	resBody, bodyErr := ioutil.ReadAll(resp.Body)
	if bodyErr != nil {
		return nil, bodyErr
	}
	log.Infof("response body for %v: %v", u.String(), string(resBody))
	return resBody, nil
}

// gets all parameters of a tenant
func (a *Adapter) getParametersHTTPRequest(tenantID string, uQuery string) (mgmtGetParametersResponse, error) {
	resBody, err := a.httpGetRequest(a.policyURL, path.Join("tenants", tenantID, "parameters"), uQuery)
	if err != nil {
		return mgmtGetParametersResponse{}, err
	}
	parameters := mgmtGetParametersResponse{}
	if err = json.Unmarshal(resBody, &parameters); err != nil {
		return mgmtGetParametersResponse{}, errors.Wrapf(err, "failed to unmarshal parameter from %v", string(resBody))
	}
	return parameters, nil
}

// gets a specific override parameter of a tenant
func (a *Adapter) getParameterHTTPRequest(tenantID string, parameterID string) (mgmtOverrideParameter, error) {
	resBody, err := a.httpGetRequest(a.policyURL, path.Join("tenants", tenantID, "parameters", parameterID), "")
	if err != nil {
		return mgmtOverrideParameter{}, err
	}
	parameter := mgmtOverrideParameter{}
	if err = json.Unmarshal(resBody, &parameter); err != nil {
		return mgmtOverrideParameter{}, errors.Wrapf(err, "failed to unmarshal parameter from %v", string(resBody))
	}
	return parameter, nil
}

// GetOverrides gets the overrides from a tenant's parameters
func (a *Adapter) GetOverrides(tenantID string) (models.TenantsOverrides, error) {
	matchKeyMap := map[string]string{
		matchSource:    models.EventTypeSource,
		matchSourceIP:  models.EventTypeSource,
		matchURL:       models.EventTypeURL,
		matchParamName: models.EventTypeParamName,
		matchParamVal:  models.EventTypeParamVal,
	}

	parameters, err := a.getParametersHTTPRequest(tenantID, "")
	if err != nil {
		return models.TenantsOverrides{}, err
	}

	log.Infof("got parameters: %v", parameters)

	overrides := models.TenantsOverrides{Matches: make(map[string][]models.OverrideData)}

	for _, parameter := range parameters.Rows {
		for _, override := range parameter.Overrides {
			overrideJSON, err := json.Marshal(override)
			if err != nil {
				return models.TenantsOverrides{}, errors.Wrapf(err, "failed to marshal overrides from %v", override)
			}
			var mgmtOverride mgmtOverrides
			err = json.Unmarshal(overrideJSON, &mgmtOverride)
			if err != nil {
				log.Infof("parameter override %v doesn't match struct", string(overrideJSON))
				break
			}
			decision := models.DecisionUnknown
			for _, behavior := range mgmtOverride.Behavior {
				for actionType, action := range behavior {
					if actionType == models.OverrideAction {
						decision = getDecisionFromBehavior(action)
					}
				}
			}
			for key, val := range mgmtOverride.Match {
				eventKey := matchKeyMap[key]
				if _, ok := overrides.Matches[eventKey]; !ok {
					overrides.Matches[eventKey] = make([]models.OverrideData, 0)
				}
				overrides.Matches[eventKey] = append(
					overrides.Matches[eventKey], models.OverrideData{
						MatchValue: val,
						Decision:   decision,
					},
				)
			}
		}
	}
	return overrides, nil
}

func getDecisionFromBehavior(action string) string {
	if action == models.ActionAccept {
		return models.DecisionBenign
	}
	return models.DecisionMalicious
}

//GetPolicyVersion return the current policy version which is incremented after every enforce
func (a *Adapter) GetPolicyVersion(tenantID string) (int, error) {
	resBody, err := a.httpGetRequest(a.policyURL, path.Join("tenants", tenantID, "policies"), "")
	if err != nil {
		return 0, errors.Wrap(err, "failed to get tenants policies")
	}
	var policy map[string]interface{}
	err = json.Unmarshal(resBody, &policy)
	if err != nil {
		return 0, errors.Wrap(err, "failed to unmarshal policies response")
	}
	version, ok := policy["version"]
	if !ok {
		return 0, errors.New("policy version not found")
	}
	return (int)(version.(float64)), nil
}

func generateParameterName(assetName string, hidden bool) string {
	if hidden {
		return parameterHiddenNamePrefix + assetName
	}
	return parameterNamePrefix + assetName
}

func (a *Adapter) getOverrideParameter(tenantID string, assetID string, hidden bool) (mgmtOverrideParameter, error) {
	ids, ok := a.parameters[tenantID][assetID]

	if ok {
		parameterID := ids.visible
		if hidden {
			parameterID = ids.hidden
		}
		if parameterID != "" {
			parameterData, err := a.getParameterHTTPRequest(tenantID, parameterID)
			if err == nil {
				log.Infof("got parameter data. id: %v, data: %v", parameterID, parameterData)
				return parameterData, nil
			}
			log.Warnf("failed to get parameter data of parameter ID: %v, err: %v", parameterID, err)
		}
	}
	if _, ok := a.parameters[tenantID]; !ok {
		a.parameters[tenantID] = make(map[string]parameterIDs)
	}
	assetData, err := a.getAsset(tenantID, assetID)
	if err != nil {
		return mgmtOverrideParameter{}, errors.Errorf("asset not found").SetClass(errors.ClassBadInput)
	}

	parameterName := generateParameterName(fmt.Sprint(assetData["name"]), hidden)

	parameters, err := a.getParametersHTTPRequest(tenantID, "searchText="+parameterName)
	if err != nil {
		return mgmtOverrideParameter{}, errors.Wrapf(
			err, "failed to get parameter data of parameter name: %v", parameterName,
		)
	}

	log.Info("parameters", parameters)

	rows := parameters.Rows
	for _, row := range rows {
		if row.Name == parameterName {
			a.updateParameterID(tenantID, assetID, hidden, row.ID)

			log.Info("return", row)
			ret := mgmtOverrideParameter{}
			temp, err := json.Marshal(row)
			if err != nil {
				return mgmtOverrideParameter{}, errors.Wrap(err, "failed to marshal row")
			}
			if err = json.Unmarshal(temp, &ret); err != nil {
				return mgmtOverrideParameter{}, errors.Wrap(err, "failed to unmarshal row")
			}
			return ret, nil
		}
	}
	return mgmtOverrideParameter{}, errors.Errorf("parameter not found").SetClass(errors.ClassNotFound)
}

func (a *Adapter) updateParameterID(tenantID string, assetID string, hidden bool, id string) {
	ids := a.parameters[tenantID][assetID]
	if hidden {
		ids.hidden = id
	} else {
		ids.visible = id
	}
	a.parameters[tenantID][assetID] = ids
}

func (a *Adapter) generateOverrideObjConditions(tuningEvents []models.TuneEvent) ([]mgmtOverrides, []mgmtOverrides) {
	tuning := make([]mgmtOverrides, 0)
	exception := make([]mgmtOverrides, 0)
	for _, tuningEvent := range tuningEvents {
		action := ""
		switch tuningEvent.Decision {
		case models.DecisionDismiss:
			fallthrough
		case models.DecisionUnknown:
			continue
		case models.DecisionMalicious:
			action = models.ActionReject
		case models.DecisionBenign:
			fallthrough
		case models.DecisionOverride:
			action = models.ActionAccept
		}
		override := mgmtOverrides{
			Match:    a.generateMatchConditions(tuningEvent),
			Behavior: []map[string]string{{models.OverrideAction: action}},
		}
		if tuningEvent.Decision == models.DecisionOverride {
			exception = append(exception, override)
		} else {
			tuning = append(tuning, override)
		}
	}
	return tuning, exception
}

func (a *Adapter) generateMatchConditions(tuningEvent models.TuneEvent) map[string]string {
	matchKeyMap := map[string]string{
		models.EventTypeSource:    matchSource,
		models.EventTypeURL:       matchURL,
		models.EventTypeParamName: matchParamName,
		models.EventTypeParamVal:  matchParamVal,
	}

	log.Infof(
		"generating match for %v(%v) to %v", matchKeyMap[tuningEvent.EventType], tuningEvent.EventType,
		tuningEvent.EventTitle,
	)

	condition := map[string]string{
		matchKeyMap[tuningEvent.EventType]: tuningEvent.EventTitle,
	}
	return condition
}

func (a *Adapter) appendParameterToAsset(tenantID string, assetID string, assetData map[string]interface{}, parameterID string) error {
	parameters, ok := assetData["parameters"]
	if !ok {
		return errors.Errorf("parameters key is missing in %v", assetData)
	}

	paramsArr, ok := parameters.([]interface{})
	if !ok {
		return errors.Errorf("parameters key is not string array %v", parameters)
	}

	paramsArr = append(paramsArr, parameterID)

	assetData["parameters"] = paramsArr

	return a.putAsset(tenantID, assetID, assetData)
}

func (a *Adapter) putAsset(tenantID string, assetID string, assetData map[string]interface{}) error {
	delete(assetData, attributeType)

	// update asset (PUT http method)
	body, err := json.Marshal(assetData)
	if err != nil {
		return err
	}
	u, err := url.Parse(a.assetURL)
	if err != nil {
		return err
	}
	u.Path = path.Join(u.Path, "tenants", tenantID, "assets", assetID)

	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to put asset. id: %v, data: %v", assetID, string(body))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Info("failed to get body from response")
		}
		return errors.Errorf(
			"%v: failed to put parameter. id: %v, data: %v, resp", resp.Status, assetID, string(body), string(respBody),
		)
	}

	return nil
}

func (a *Adapter) getAsset(tenantID string, assetID string) (map[string]interface{}, error) {
	resBody, err := a.httpGetRequest(a.assetURL, path.Join("tenants", tenantID, "assets", assetID), "")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get asset data. id: %v", assetID)
	}
	assetData := map[string]interface{}{}
	err = json.Unmarshal(resBody, &assetData)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal asset from %v", string(resBody))
	}
	return assetData, nil
}

func (a *Adapter) createParameter(tenantID string, assetID string, tuningOverrides []mgmtOverrides, hidden bool) error {
	assetData, err := a.getAsset(tenantID, assetID)
	if err != nil {
		return err
	}

	parameterName := generateParameterName(fmt.Sprint(assetData["name"]), hidden)

	parameterData := mgmtOverrideParameter{
		Name:      parameterName,
		Comment:   "",
		ParamType: "Overrides",
	}

	parameterData.Overrides = tuningOverrides

	// post to MGMT
	body, err := json.Marshal(parameterData)
	if err != nil {
		return err
	}
	u, err := url.Parse(a.policyURL)
	if err != nil {
		return err
	}
	u.Path = path.Join(u.Path, "tenants", tenantID, "parameters")
	resp, err := a.HTTPClient.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return errors.Wrapf(err, "failed to post %v", string(body))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Warn("failed to read failure response")
		}
		return errors.Errorf("got %v: %v on post %v : %v", resp.Status, string(respBody), u.String(), string(body))
	}

	// save parameter ID for future use
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var newParam map[string]interface{}
	err = json.Unmarshal(resBody, &newParam)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal response body")
	}

	if _, ok := a.parameters[tenantID]; !ok {
		a.parameters[tenantID] = make(map[string]parameterIDs)
	}
	id := fmt.Sprint(newParam["id"])
	a.updateParameterID(tenantID, assetID, hidden, id)

	err = a.appendParameterToAsset(tenantID, assetID, assetData, id)
	if err != nil {
		return errors.Wrapf(err, "failed to append parameter to asset")
	}

	return nil
}

// AppendParameters generate overrides for tuningEvents and append to existing parameter, create it otherwise
func (a *Adapter) AppendParameters(tenantID string, assetID string, tuningEvents []models.TuneEvent) error {
	genTuningItems, exceptionItems := a.generateOverrideObjConditions(tuningEvents)
	if len(genTuningItems) == 0 && len(exceptionItems) == 0 {
		log.Info("no new tuning events, nothing to do")
		return nil
	}
	// handle appending tuning items to the hidden (in UI) parameter
	err := a.appendToParameter(tenantID, assetID, tuningEvents, genTuningItems, true)
	if err != nil {
		return errors.Wrap(err, "failed to append to hidden parameter")
	}
	// handle appending tuning items to the visible (in UI) parameter
	return a.appendToParameter(tenantID, assetID, tuningEvents, exceptionItems, false)
}

func (a *Adapter) appendToParameter(tenantID string, assetID string, tuningEvents []models.TuneEvent, genTuningItems []mgmtOverrides, hidden bool) error {
	if len(genTuningItems) == 0 {
		return nil
	}
	parameterData, err := a.getOverrideParameter(tenantID, assetID, hidden)
	if err != nil {
		if errors.IsClass(err, errors.ClassNotFound) {
			return a.createParameter(tenantID, assetID, genTuningItems, hidden)
		}
		return err
	}

	parameterData.Overrides = append(parameterData.Overrides, genTuningItems...)

	return a.putParameter(tenantID, parameterData)
}

func (a *Adapter) putParameter(tenantID string, parameterData mgmtOverrideParameter) error {
	// update parameter (PUT http method)
	body, err := json.Marshal(parameterData)
	if err != nil {
		return err
	}
	u, err := url.Parse(a.policyURL)
	if err != nil {
		return err
	}
	u.Path = path.Join(u.Path, "tenants", tenantID, "parameters", parameterData.ID)

	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to put parameter. id: %v, data: %v", parameterData.ID, string(body))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Info("failed to get body from response")
		}
		return errors.Errorf(
			"%v: failed to put parameter. id: %v, data: %v, resp", resp.Status, parameterData.ID, string(body),
			string(respBody),
		)
	}
	return nil
}

func (a *Adapter) removeOverridesFromParameter(overrides []mgmtOverrides, events []models.TuneEvent) []mgmtOverrides {
	for _, tuneEvent := range events {
		eventMatch := a.generateMatchConditions(tuneEvent)
		for i, override := range overrides {
			for k, v := range override.Match {
				if v == eventMatch[k] && len(override.Behavior) > 0 {
					for _, behavior := range override.Behavior {
						if _, ok := behavior["action"]; !ok {
							continue
						}
						return append(overrides[:i], overrides[i+1:]...)
					}
				}
			}
		}
	}
	return overrides
}

func splitTuningEventsByHidden(tuningEvents []models.TuneEvent) (visible []models.TuneEvent, hidden []models.TuneEvent) {
	hidden = make([]models.TuneEvent, 0)
	visible = make([]models.TuneEvent, 0)
	for _, event := range tuningEvents {
		if event.Decision == models.DecisionOverride {
			visible = append(visible, event)
		} else if event.Decision == models.DecisionBenign || event.Decision == models.DecisionMalicious {
			hidden = append(hidden, event)
		}
	}
	return visible, hidden
}

func (a *Adapter) removeParameter(tenantID string, assetID string, tuningEvents []models.TuneEvent, hidden bool) error {
	if len(tuningEvents) == 0 {
		return nil
	}
	parameterData, err := a.getOverrideParameter(tenantID, assetID, hidden)
	if err != nil {
		return err
	}
	parameterData.Overrides = a.removeOverridesFromParameter(parameterData.Overrides, tuningEvents)
	if len(parameterData.Overrides) == 0 {
		a.updateParameterID(tenantID, assetID, hidden, "")
		return a.deleteParameter(tenantID, assetID, parameterData.ID)
	}
	return a.putParameter(tenantID, parameterData)
}

// RemoveParameters remove override from parameter
func (a *Adapter) RemoveParameters(tenantID string, assetID string, tuningEvents []models.TuneEvent) error {
	if len(tuningEvents) == 0 {
		return nil
	}
	visible, hidden := splitTuningEventsByHidden(tuningEvents)

	err := a.removeParameter(tenantID, assetID, visible, false)
	if err != nil {
		return err
	}

	return a.removeParameter(tenantID, assetID, hidden, true)
}

func (a *Adapter) deleteParameter(tenantID string, assetID string, parameterID string) error {
	err := a.removeParameterFromAsset(tenantID, assetID, parameterID)
	if err != nil {
		return err
	}
	u, err := url.Parse(a.policyURL)
	if err != nil {
		return err
	}
	u.Path = path.Join(u.Path, "tenants", tenantID, "parameters", parameterID)

	req, err := http.NewRequest(http.MethodDelete, u.String(), nil)
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to delete parameter. id: %v", parameterID)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf(
				"%v: failed to put parameter. id: %v, failed to get response body", resp.Status, parameterID,
			)
		}
		return errors.Errorf(
			"%v: failed to put parameter. id: %v, resp %v", resp.Status, parameterID, string(respBody),
		)
	}
	return nil
}

func (a *Adapter) removeParameterFromAsset(tenantID string, assetID string, parameterID string) error {
	assetData, err := a.getAsset(tenantID, assetID)
	if err != nil {
		return errors.Wrap(err, "failed to get asset data")
	}
	parameters, ok := assetData["parameters"]
	if !ok {
		return errors.Errorf("parameters key is missing in %v", assetData)
	}

	paramsArr, ok := parameters.([]interface{})
	if !ok {
		return errors.Errorf("parameters key is not string array %v", parameters)
	}

	for i, param := range paramsArr {
		if fmt.Sprint(param) == parameterID {
			paramsArr = append(paramsArr[:i], paramsArr[i+1:]...)
			break
		}
	}

	assetData["parameters"] = paramsArr
	return a.putAsset(tenantID, assetID, assetData)
}
