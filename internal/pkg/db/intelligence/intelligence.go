package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"openappsec.io/ctxutils"

	intelModels "openappsec.io/intelligencesdk/models"
	"openappsec.io/intelligencesdk/pkg/sdk"
	"openappsec.io/smartsync-tuning/models"
	"openappsec.io/errors"
	"openappsec.io/log"
)

const (
	initializeTimeout = time.Minute
	tuningSourceID    = "ngen.checkpoint.tuningSrv"

	confKeyIntelligenceBase                 = "intelligence."
	confKeyIntelligenceHost                 = confKeyIntelligenceBase + "host"
	confKeyIntelligenceTimeout              = confKeyIntelligenceBase + "timeout"
	confKeyIntelligenceRegistrationBase     = confKeyIntelligenceBase + "registration."
	confKeyIntelligenceRegistrationPeriod   = confKeyIntelligenceRegistrationBase + "period"
	confKeyIntelligenceRegistrationRequest  = confKeyIntelligenceRegistrationBase + "request"
	confKeyIntelligenceRegistrationTenantID = confKeyIntelligenceRegistrationBase + "tenantId"
	confKeyIntelligenceRegistrationSourceID = confKeyIntelligenceRegistrationBase + "sourceId"

	maxRetries = 2
	// TTL set to 48 hours (172800 seconds)
	defaultTTL = 172800
)

// mockgen -destination mocks/mock_dbIntelligence.go -package mocks -source internal/pkg/db/intelligence/intelligence.go -mock_names Configuration=MockIntelligenceConfiguration

// SDK defines the SDK interface
type SDK interface {
	Live(ctx context.Context) error
	Ready(ctx context.Context) error
	PostAssets(ctx context.Context, identity intelModels.Identity, updateExistingAssets bool, ass intelModels.Assets) (intelModels.ReportResponse, error)
	GetAsset(ctx context.Context, identity intelModels.Identity, assetID string) (intelModels.Asset, error)
	SimpleQueryIntelAssets(ctx context.Context,
		identity intelModels.Identity,
		query map[string]string,
		limit *int,
		offset *int,
		requestedAttributes []string,
		minConfidence *int) (intelModels.QueryResponse, error)
	QueryIntelAssetsV2(ctx context.Context,
		identity intelModels.Identity,
		query intelModels.IntelQueryV2) (intelModels.QueryResponseAssets, error)
	RegisterExternalSource(
		ctx context.Context,
		identity intelModels.Identity, extSrcReg intelModels.ExternalSourceReg,
	) (string, error)
	Invalidation(ctx context.Context,
		identity intelModels.Identity,
		invalidations intelModels.ReportedInvalidations,
	) error
}

// Configuration used to get the configuration of the intelligence host
type Configuration interface {
	GetString(key string) (string, error)
	GetDuration(key string) (time.Duration, error)
}

// Adapter to intelligence DB sdk
type Adapter struct {
	sdkAdapter       SDK
	host             string
	sourceID         string
	intelRegPeriod   time.Duration
	intelRegIdentity intelModels.Identity
	intelRegRequest  intelModels.ExternalSourceReg
}

// NewAdapter creates a new adapter
func NewAdapter(c Configuration) (*Adapter, error) {
	a := &Adapter{}
	host, err := c.GetString(confKeyIntelligenceHost)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get intelligence host from configuration")
	}

	timeout, err := c.GetDuration(confKeyIntelligenceTimeout)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get intelligence timeout from configuration")
	}

	intelRegPeriod, err := c.GetDuration(confKeyIntelligenceRegistrationPeriod)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get intelligence registration period from configuration")
	}

	if intelRegPeriod < initializeTimeout {
		return nil, errors.Errorf(
			"Invalid registration period (%s), minimum is (%s)",
			intelRegPeriod,
			initializeTimeout,
		)
	}

	if intelRegPeriod < timeout {
		return nil, errors.New("intelligence timeout can't be greater then registration period")
	}

	intelRegRequest, err := c.GetString(confKeyIntelligenceRegistrationRequest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get registration request from configuration")
	}

	intelRegRequestBytes := []byte(intelRegRequest)
	var intelRegRequestUnmarshall intelModels.ExternalSourceReg
	if err = json.Unmarshal(intelRegRequestBytes, &intelRegRequestUnmarshall); err != nil {
		return nil, errors.Wrapf(
			err,
			"failed to unmarshal intelligence registration request from configuration %v",
			intelRegRequest,
		)
	}

	intelRegTenantID, err := c.GetString(confKeyIntelligenceRegistrationTenantID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get registration tenant id from configuration")
	}

	intelRegSourceID, err := c.GetString(confKeyIntelligenceRegistrationSourceID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get source ID from configuration")
	}

	a.host = host

	a.sdkAdapter, err = sdk.NewAdapter(a.host, timeout)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize intelligence adapter")
	}

	intelRegIdentity := intelModels.Identity{
		TenantID: intelRegTenantID,
		SourceID: intelRegSourceID,
	}
	a.intelRegIdentity = intelRegIdentity
	a.intelRegRequest = intelRegRequestUnmarshall
	a.intelRegPeriod = intelRegPeriod
	a.sourceID = tuningSourceID
	return a, nil
}

// ReportAsset data for an assetID in tenantID
func (a *Adapter) ReportAsset(ctx context.Context, reportType models.ReportedAssetType, tenantID string, assetID string, data interface{}) error {
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyAPIVersion, intelModels.APIV2)
	log.WithContext(ctx).Infof("reporting %v for tenant: %v, asset: %v, data: %v", reportType, tenantID, assetID, data)

	if tenantID == "" || assetID == "" || data == nil {
		return errors.Errorf(
			"missing argument. tenantID(%v) and assetID(%v) and data(%v) should not be empty", tenantID, assetID, data,
		)
	}

	asset, err := a.getAssetByID(ctx, tenantID, assetID)
	if err != nil {
		return err
	}

	ad, err := a.getAssetData(ctx, tenantID, asset.AssetID)
	if err != nil && !errors.IsClass(err, errors.ClassNotFound) {
		return errors.Wrap(err, "failed to get asset data")
	}

	ad.MgmtID = assetID

	switch reportType {
	case models.ReportStatistics:
		err = convertUsingJSON(data, &ad.Statistics)
		if err != nil {
			return err
		}
	case models.ReportTuning:
		err = convertUsingJSON(data, &ad.TuningEvents)
		if err != nil {
			return err
		}
	case models.ReportTuningDecided:
		err = convertUsingJSON(data, &ad.TuningEventsDecided)
		if err != nil {
			return err
		}
	case models.ReportAssetPolicyData:
		err = convertUsingJSON(data, &ad.TrustedSourcesPolicy)
	default:
		return errors.Errorf("unknown report type: %v", reportType)
	}
	asset.Attributes = map[string]interface{}{"calculated": "true", "data": ad}
	asset.TTL = defaultTTL
	asset.ExpirationTime = nil
	asset.SourceID = ""
	asset.TenantID = ""
	asset.AssetID = ""
	if asset.SchemaVersion == 0 {
		asset.SchemaVersion = 1
		asset.PermissionType = "tenant"
		asset.AssetType = fmt.Sprintf("%v-%v-%v", asset.Class, asset.Category, asset.Family)
		asset.AssetTypeSchemaVersion = 1
	}

	resp, err := a.sdkAdapter.PostAssets(
		ctx,
		intelModels.Identity{TenantID: tenantID, SourceID: a.sourceID},
		true,
		intelModels.Assets{asset},
	)

	if err != nil {
		return errors.Wrap(err, "fail to post asset")
	}

	if len(resp.IDs) == 0 {
		log.WithContext(ctx).Warn("did not get ids from post assets")
	}

	return err
}

// GetAssetData return the reportType data stored for assetID in tenantID
func (a *Adapter) GetAssetData(ctx context.Context, reportType models.ReportedAssetType, tenantID string, assetID string, out interface{}) error {
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyAPIVersion, intelModels.APIV2)
	asset, err := a.getAssetByID(ctx, tenantID, assetID)
	if err != nil {
		return err
	}

	data, err := a.getAssetData(ctx, tenantID, asset.AssetID)
	if err != nil {
		return err
	}

	log.WithContext(ctx).Infof("asset data: %v", data)
	switch reportType {
	case models.ReportAssetPolicyData:
		convertUsingJSON(data.TrustedSourcesPolicy, out)
	case models.ReportAll:
		o, ok := out.(*models.Attributes)
		if !ok {
			return errors.New("failed to cast out")
		}
		data.ApplicationUrls = fmt.Sprint(asset.MainAttributes["applicationUrls"])
		*o = data
		out = o
	case models.ReportStatistics:
		convertUsingJSON(data.Statistics, out)
	case models.ReportTuning:
		sort.Slice(
			data.TuningEvents, func(i, j int) bool {
				if data.TuningEvents[i].Severity == data.TuningEvents[j].Severity {
					return false
				}
				if data.TuningEvents[i].Severity == "critical" {
					return true
				}
				return false
			},
		)
		convertUsingJSON(data.TuningEvents, out)
	case models.ReportTuningDecided:
		convertUsingJSON(data.TuningEventsDecided, out)
	default:
		return errors.Errorf("unknown report type: %v", reportType)
	}
	return nil
}

func convertUsingJSON(in interface{}, out interface{}) error {
	assetJSON, err := json.Marshal(in)
	if err != nil {
		return err
	}
	err = json.Unmarshal(assetJSON, out)
	if err != nil {
		return err
	}
	return nil
}

//GetMgmtAsset returns the mgmt asset
func (a *Adapter) GetMgmtAsset(ctx context.Context, tenantID string, assetID string) (intelModels.Asset, error) {
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyAPIVersion, intelModels.APIV2)
	asset, err := a.getAssetByID(ctx, tenantID, assetID)
	if err != nil {
		return intelModels.Asset{},
			errors.Wrapf(err, "failed to get main attributes for tenant: %v, asset: %v", tenantID, assetID)
	}
	return asset, nil
}

func (a *Adapter) getAssetData(ctx context.Context, tenantID string, assetID string) (models.Attributes, error) {
	defaultRet := models.Attributes{
		Statistics:           models.Statistics{},
		TuningEvents:         []models.TuneEvent{},
		TuningEventsDecided:  []models.TuneEvent{},
		TrustedSourcesPolicy: models.TrustedSourcesPolicy{},
	}
	repoAsset, err := a.sdkAdapter.GetAsset(
		ctx,
		intelModels.Identity{TenantID: tenantID, SourceID: a.sourceID},
		assetID,
	)
	if err != nil {
		return defaultRet, errors.Wrapf(
			err,
			"failed to get asset from intelligence. asset ID: %v", assetID,
		).SetClass(errors.ClassNotFound)
	}
	ass := intelModels.Asset{}
	err = convertUsingJSON(repoAsset, &ass)
	if err != nil {
		return defaultRet, err
	}

	attributes := ass.Attributes
	data, ok := attributes["data"]
	if !ok {
		log.WithContext(ctx).Debug("missing data field in attributes", repoAsset)
		return defaultRet, nil
	}
	ad := models.Attributes{}
	err = convertUsingJSON(data, &ad)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to convert %v into assetData type", data)
		return defaultRet, nil
	}
	return ad, nil
}

func (a *Adapter) getAssetByID(ctx context.Context, tenantID string, assetID string) (intelModels.Asset, error) {
	query := intelModels.IntelQueryV2{
		Query: intelModels.Query{
			Operator: "AND",
			Operands: []intelModels.Query{
				{
					Operator: "NOT_EQUALS",
					Key:      "class",
					Value:    "true",
				},
				{
					Operator: "EQUALS",
					Key:      "attributes.id",
					Value:    assetID,
				},
			},
		},
	}
	identity := intelModels.Identity{
		TenantID: tenantID,
		SourceID: a.sourceID,
	}
	resp, err := a.sdkAdapter.QueryIntelAssetsV2(ctx, identity, query)

	if err != nil {
		return intelModels.Asset{}, errors.Wrapf(
			err, "assetID %v not found, query failed", assetID,
		).SetClass(errors.ClassInternal)
	}

	for i := 0; i < maxRetries && resp.Status != intelModels.QueryResultStatusDone; i++ {
		time.Sleep(time.Second)
		log.WithContext(ctx).Infof("retry query for asset")
		resp, err = a.sdkAdapter.QueryIntelAssetsV2(ctx, identity, query)

		if err != nil {
			return intelModels.Asset{}, errors.Wrapf(
				err, "assetID %v not found, query failed", assetID,
			).SetClass(errors.ClassInternal)
		}
	}

	if resp.Status != intelModels.QueryResultStatusDone {
		log.WithContext(ctx).Warnf("intelligence query timeout for asset: %v and tenant: %v", assetID, tenantID)
	}

	if len(resp.Assets) == 0 {
		return intelModels.Asset{}, errors.Errorf(
			"assetID %v not found, empty response", assetID,
		).SetClass(errors.ClassUnauthorized)
	}
	log.WithContext(ctx).Info("intelligence query response", resp)
	return resp.Assets[0], nil
}

// RegistrationHeartbeat registers the aux service to intelligence periodically
func (a *Adapter) RegistrationHeartbeat(ctx context.Context) {
	a.register(ctx)
	ticker := time.NewTicker(a.intelRegPeriod)

	for {
		select {
		case <-ticker.C:
			a.register(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (a *Adapter) register(ctx context.Context) {
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyAPIVersion, intelModels.APIV2)
	id, err := a.sdkAdapter.RegisterExternalSource(ctx, a.intelRegIdentity, a.intelRegRequest)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to register to intelligence: %v", err)
		return
	}

	log.WithContext(ctx).Debugf("Successfully registered to intelligence, got id: %s", id)
	return
}

// InitTenantInvalidation invalidates all assets associated with the given tenant ID
// this is done during the "init tenant" process
func (a *Adapter) InitTenantInvalidation(ctx context.Context, tenantID string) error {
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyAPIVersion, intelModels.APIV2)
	invalidation := intelModels.InvalidationData{
		Class:      "workload",
		Category:   "cloud",
		Group:      "",
		Order:      "",
		Kind:       "",
		ObjectType: "asset",
	}

	invalidationIdentity := intelModels.Identity{
		TenantID: tenantID,
		SourceID: a.sourceID,
	}

	if err := a.sdkAdapter.Invalidation(ctx, invalidationIdentity,
		intelModels.ReportedInvalidations{InvalidationsData: intelModels.InvalidationsData{invalidation}}); err != nil {
		return errors.Wrapf(err, "failed to invalidate assets")
	}

	return nil
}

//Invalidate the data stored in intelligence cache
func (a *Adapter) Invalidate(ctx context.Context,
	tenantID string,
	attr models.Attributes) {
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyAPIVersion, intelModels.APIV2)

	invalidAsset := intelModels.InvalidationData{
		Class:    "workload",
		Category: "cloud",
		Family:   attr.Family,
		Group:    "",
		Order:    "",
		Kind:     "",
		MainAttributes: []intelModels.MainAttributes{{
			"applicationUrls": attr.ApplicationUrls,
		}},
		ObjectType: "asset",
	}
	id := intelModels.Identity{
		TenantID: tenantID,
		SourceID: a.sourceID,
	}
	err := a.sdkAdapter.Invalidation(
		ctx,
		id,
		intelModels.ReportedInvalidations{
			InvalidationsData: intelModels.InvalidationsData{invalidAsset},
		})

	if err != nil {
		log.WithContext(ctx).Warnf("failed to invalidate asset for tenant: %v, error: %v", tenantID, err)
	}
}
