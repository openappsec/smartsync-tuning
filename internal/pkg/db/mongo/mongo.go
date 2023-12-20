package mongo

import (
	"context"
	"fmt"
	"strings"

	"openappsec.io/ctxutils"

	intel "openappsec.io/intelligencesdk/models"

	"openappsec.io/smartsync-tuning/models"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"openappsec.io/errors"
	"openappsec.io/log"
	"openappsec.io/mongodb"
)

const (
	repoConfBaseKey   = "mongo"
	repoURIKey        = repoConfBaseKey + ".uri"
	repoDatabaseKey   = repoConfBaseKey + ".database"
	repoCollectionKey = repoConfBaseKey + ".collection"
)

// DB represents the interface of a database
type DB interface {
	Connect(ctx context.Context, mongodbConfiguration mongodb.MongoConfig) error
	CreateIndex(ctx context.Context, index []mongodb.Index, unique bool, opts ...*mongodb.IndexOptions) error
	CreateTTLIndex(ctx context.Context, field string, indexType mongodb.IndexType, ttl int32) error
	UpdateOne(
		ctx context.Context,
		filter map[string]interface{},
		update mongodb.UpdateOperators,
		upsert bool,
	) (mongodb.UpdateResult, error)
	GetByQuery(
		ctx context.Context,
		filter map[string]interface{},
		results interface{},
		opts ...*mongodb.QueryOptions,
	) error
	DeleteByQuery(ctx context.Context, filter map[string]interface{}) (int64, error)
	HealthCheck(ctx context.Context) (string, error)
	TearDown(ctx context.Context) error
}

// RepositoryBC represents the interface to the previous repository
type RepositoryBC interface {
	GetAssetData(
		ctx context.Context,
		reportedType models.ReportedAssetType,
		tenantID string,
		assetID string,
		out interface{},
	) error
	GetMgmtAsset(
		ctx context.Context,
		tenantID string,
		assetID string,
	) (intel.Asset, error)
	Invalidate(
		ctx context.Context,
		tenantID string,
		attr models.Attributes,
	)
}

// Configuration exposes an interface of configuration related actions
type Configuration interface {
	GetString(key string) (string, error)
}

// Adapter is the adapter to the mongodb library
type Adapter struct {
	mdb DB
	bc  RepositoryBC
}

type document struct {
	TuningID   string             `bson:"tuningId,omitempty"`
	Attributes *models.Attributes `bson:"attributes,omitempty"`
}

type policyDocument struct {
	TenantID      string `bson:"tenantId,omitempty"`
	PolicyVersion int64  `bson:"policyVersion,omitempty"`
}

// NewAdapter creates and configure a new adapter to mongodb
func NewAdapter(conf Configuration, db DB, bc RepositoryBC) (*Adapter, error) {
	uri, err := conf.GetString(repoURIKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get mongodb uri")
	}

	database, err := conf.GetString(repoDatabaseKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get mongodb database")
	}

	collection, err := conf.GetString(repoCollectionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get mongodb collection")
	}

	mongoConfig := mongodb.MongoConfig{
		URI:        uri,
		Database:   database,
		Collection: collection,
	}

	err = db.Connect(context.Background(), mongoConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to mongodb, config: %+v", mongoConfig)
	}

	return &Adapter{db, bc}, nil
}

// ReportAsset data for an assetID in tenantID
func (a *Adapter) ReportAsset(
	ctx context.Context,
	reportedType models.ReportedAssetType,
	tenant string,
	asset string,
	data interface{},
) error {
	tuningID := genTuningID(tenant, asset)
	filter := map[string]interface{}{
		"tuningId": tuningID,
	}

	log.WithContext(ctx).Infof("report to mongo: id: %v, attributes: %+v", tuningID, data)

	var attr models.Attributes
	if reportedType != models.ReportAll {
		err := a.getAssetData(ctx, models.ReportAll, tenant, asset, &attr, reportedType == models.ReportAssetPolicyData)
		if err != nil {
			if errors.IsClass(err, errors.ClassUnauthorized) {
				// asset does not exist in management so delete service copy
				return a.deleteAsset(ctx, genTuningID(tenant, asset))
			} else if !errors.IsClass(err, errors.ClassNotFound) {
				return err
			}
		}
		log.WithContext(ctx).Infof("original attributes are: %+v", attr)
	} else {
		ok := false
		attr, ok = data.(models.Attributes)
		if ok {
			log.WithContext(ctx).Infof("original attributes overwritten: %+v", attr)
		} else {
			log.WithContext(ctx).Errorf("failed to convert from %T to %T", data, attr)
		}
	}

	update, err := a.genUpdateOperators(ctx, reportedType, tuningID, attr, data)

	if err != nil {
		return errors.Wrapf(
			err,
			"failed to generate update operators for tuning ID: %v, reportType: %v, data: %+v",
			tuningID,
			reportedType,
			data,
		)
	}

	updateRes, err := a.mdb.UpdateOne(ctx, filter, update, true)

	log.WithContext(ctx).Infof("call update once(%+v, %+v) = %+v, %+v", filter, update, updateRes, err)

	if err != nil {
		return errors.Wrapf(err, "failed to update document: %+v", update)
	}
	if updateRes.MatchedCount == 0 && updateRes.UpsertedCount == 0 {
		return errors.Errorf("failed to find or insert document for filter %+v", filter)
	}

	if attr.ApplicationUrls != "" {
		a.bc.Invalidate(ctx, tenant, attr)
	}

	return nil
}

func (a *Adapter) genUpdateOperators(
	ctx context.Context,
	reportedType models.ReportedAssetType,
	tuningID string,
	attr models.Attributes,
	data interface{},
) (mongodb.UpdateOperators, error) {
	updateOps := mongodb.UpdateOperators{SetOnInsert: document{TuningID: tuningID}}
	switch reportedType {
	case models.ReportCertificateInstallationStatus:
		conv, ok := data.(models.CertInstallStatus)
		if !ok {
			return updateOps, errors.Errorf("failed to convert data %+v to CertInstallStatus", data)
		}
		if attr.CertInstallStatus == nil {
			attr.CertInstallStatus = map[string]models.CertInstallStatus{}
		}
		if conv.URL == "" {
			attr.CertInstallStatus = map[string]models.CertInstallStatus{}
		} else if _, ok := attr.CertInstallStatus[""]; ok {
			delete(attr.CertInstallStatus, "")
		}
		attr.CertInstallStatus[conv.URL] = conv
	case models.ReportUpstreamHealthcheckStatus:
		conv, ok := data.(models.UpstreamStatus)
		if !ok {
			return updateOps, errors.Errorf("failed to convert data %+v to UpstreamHealthcheck", data)
		}
		if attr.UpstreamStatus == nil {
			attr.UpstreamStatus = map[string]models.UpstreamHealthcheck{}
		}
		attr.UpstreamStatus[conv.Data.Agent] = conv.Data
		if attr.AgentVersion == nil {
			attr.AgentVersion = map[string]string{}
		}
		attr.AgentVersion[conv.Data.Agent] = conv.Version
	case models.ReportStatistics:
		conv, ok := data.(models.Statistics)
		if !ok {
			return updateOps, errors.Errorf("failed to convert data %+v to statistics", data)
		}
		attr.Statistics = conv
	case models.ReportTuning:
		conv, ok := data.([]models.TuneEvent)
		if !ok {
			return updateOps, errors.Errorf("failed to convert data %+v to tuning events", data)
		}
		attr.TuningEvents = conv
	case models.ReportTuningDecided:
		conv, ok := data.([]models.TuneEvent)
		if !ok {
			return updateOps, errors.Errorf("failed to convert data %+v to tuning events", data)
		}
		attr.TuningEventsDecided = conv
	case models.ReportTrustedSourcesPolicy:
		conv, ok := data.(models.TrustedSourcesPolicy)
		if !ok {
			return updateOps, errors.Errorf("failed to convert data %+v to trusted sources policy", data)
		}
		attr.TrustedSourcesPolicy = conv
	case models.ReportAssetExceptions:
		conv, ok := data.(models.AssetExceptions)
		if !ok {
			return updateOps, errors.Errorf("failed to convert data %+v to asset exceptions", data)
		}
		attr.AssetExceptions = conv
	case models.ReportAssetPolicyData:
		conv, ok := data.(models.AssetDetails)
		if !ok {
			return updateOps, errors.Errorf("failed to convert data %+v to trusted sources policy", data)
		}
		attr.TrustedSourcesPolicy = conv.TrustedSources
		attr.Name = conv.Name
		attr.ApplicationUrls = conv.ApplicationUrls
		attr.Statistics.MitigationMode = conv.Mode
		attr.Statistics.MitigationLevel = conv.Level
		attr.MgmtID = conv.AssetID
		attr.PolicyVersion = conv.PolicyVersion
		if conv.Type == models.WaapTypeWebApp {
			attr.Family = "Web Application"
			attr.Type = "WebApplication"
		} else if conv.Type == models.WaapTypeWebAPI {
			attr.Family = "Web API"
			attr.Type = "WebAPI"
		} else {
			return updateOps, errors.Errorf("unrecognized asset type: %v", conv.Type)
		}
	case models.ReportAll:
		conv, ok := data.(models.Attributes)
		if !ok {
			return updateOps, errors.Errorf("failed to convert data %+v to tuning attributes", data)
		}
		attr = conv
	default:
		return updateOps, errors.Errorf("unrecognized report type: %v", reportedType)
	}
	if (attr.ApplicationUrls == "" || attr.Name == "") && reportedType == models.ReportAll {
		ids := strings.Split(tuningID, "_")
		if len(ids) == 2 {
			mgmtAsset, err := a.bc.GetMgmtAsset(ctx, ids[0], ids[1])
			if err != nil {
				log.WithContext(ctx).Warnf("failed to update application urls, err: %v", err)
			} else {
				attr.ApplicationUrls = fmt.Sprint(mgmtAsset.MainAttributes["applicationUrls"])
				attr.Name = mgmtAsset.Name
				attr.Type = mgmtAsset.AssetType
				attr.Family = mgmtAsset.Family
			}
		}
	}
	updateOps.Set = document{Attributes: &attr}
	log.WithContext(ctx).Infof("update attributes: %+v", attr)
	return updateOps, nil
}

// GetAssetData return the reportType data stored for assetID in tenantID
func (a *Adapter) GetAssetData(
	ctx context.Context,
	reportedType models.ReportedAssetType,
	tenantID string,
	assetID string,
	out interface{},
) error {
	return a.getAssetData(ctx, reportedType, tenantID, assetID, out, false)
}

func (a *Adapter) getAssetData(
	ctx context.Context,
	reportedType models.ReportedAssetType,
	tenantID string,
	assetID string,
	out interface{},
	allowEmpty bool,
) error {
	tuningID := genTuningID(tenantID, assetID)
	filter := map[string]interface{}{"tuningId": tuningID}

	docs, err := a.runMongoQuery(ctx, filter)
	if err != nil {
		return errors.Wrap(err, "failed to run query in mongo")
	}

	for i, doc := range docs {
		log.WithContext(ctx).Infof("mongo query res(%v) attributes: %+v", i, doc.Attributes)
	}

	var res interface{}

	if len(docs) == 0 || (docs[0].Attributes.MgmtID == "" && reportedType == models.ReportAll) {
		log.WithContext(ctx).Infof("checking for BC data for tenant: %v, asset: %v", tenantID, assetID)
		attr := models.Attributes{}
		if !allowEmpty {
			err = a.bc.GetAssetData(ctx, models.ReportAll, tenantID, assetID, &attr)
			if err != nil {
				return errors.Wrap(err, "failed to query for asset data")
			}
			err = a.ReportAsset(ctx, models.ReportAll, tenantID, assetID, attr)
			if err != nil {
				return errors.Wrap(err, "failed to report asset data from BC repo")
			}
		}
		err = setOutArgFromAttributes(reportedType, &attr, &res)
	} else {
		if docs[0].Attributes.ApplicationUrls == "" && reportedType == models.ReportAll {
			mgmtAsset, err := a.bc.GetMgmtAsset(ctx, tenantID, assetID)
			if err != nil {
				return errors.Wrapf(
					err,
					"failed to get application urls from main attributes",
				).SetClass(errors.ClassNotFound)
			}
			docs[0].Attributes.ApplicationUrls = fmt.Sprint(mgmtAsset.MainAttributes["applicationUrls"])
			docs[0].Attributes.Name = mgmtAsset.Name
			docs[0].Attributes.Type = mgmtAsset.AssetType
			docs[0].Attributes.Family = mgmtAsset.Family
			a.ReportAsset(ctx, models.ReportAll, tenantID, assetID, *docs[0].Attributes)
		}

		err = setOutArgFromAttributes(reportedType, docs[0].Attributes, &res)
	}
	if ptr, ok := out.(*interface{}); ok {
		*ptr = res
	} else if ptr, ok := out.(*models.Attributes); ok {
		*ptr = *res.(*models.Attributes)
	} else {
		log.WithContext(ctx).Warnf("Unrecognized input type: %T", out)
		return errors.New("unrecognized output type").SetClass(errors.ClassInternal)
	}
	return err
}

func genTuningID(tenantID string, assetID string) string {
	return fmt.Sprintf("%v_%v", tenantID, assetID)
}

func setOutArgFromAttributes(reportedType models.ReportedAssetType, attr *models.Attributes, out *interface{}) error {
	switch reportedType {
	case models.ReportStatistics:
		*out = &attr.Statistics
		return nil
	case models.ReportTuningDecided:
		if attr.TuningEventsDecided == nil {
			*out = &[]models.TuneEvent{}
			return nil
		}
		*out = &attr.TuningEventsDecided
		return nil
	case models.ReportTuning:
		if attr.TuningEvents == nil {
			*out = &[]models.TuneEvent{}
			return nil
		}
		*out = &attr.TuningEvents
		return nil
	case models.ReportTrustedSourcesPolicy:
		*out = &attr.TrustedSourcesPolicy
		return nil
	case models.ReportAssetExceptions:
		*out = &attr.AssetExceptions
		return nil
	case models.ReportAll:
		*out = attr
		return nil
	}

	return errors.Errorf("unrecognized response report type: %v", reportedType)
}

func genQueryArgs(reportedType models.ReportedAssetType) (mongodb.QueryOptions, error) {
	opt := mongodb.QueryOptions{Projection: map[string]int{"attributes.mgmtId": 1, "tuningId": 1}}
	switch reportedType {
	case models.ReportStatistics:
		opt.Projection["attributes.statistics"] = 1
		return opt, nil
	case models.ReportTuning:
		opt.Projection["attributes.tuningEvents"] = 1
		return opt, nil
	case models.ReportTuningDecided:
		opt.Projection["attributes.tuningEventsDecided"] = 1
		return opt, nil
	case models.ReportTrustedSourcesPolicy:
		opt.Projection["attributes.trustedSourcesPolicy"] = 1
		return opt, nil
	case models.ReportAssetExceptions:
		opt.Projection["attributes.assetExceptions"] = 1
		return opt, nil
	case models.ReportAssetPolicyData:
		opt.Projection["attributes.trustedSourcesPolicy"] = 1
		opt.Projection["attributes.statistics"] = 1
	case models.ReportAll:
		opt.Projection = map[string]int{"attributes": 1, "tuningId": 1}
		return opt, nil
	}
	return mongodb.QueryOptions{}, errors.Errorf("unrecognized query report type: %v", reportedType)
}

// TearDown disconnect gracefully from mongodb
func (a *Adapter) TearDown(ctx context.Context) error {
	return a.mdb.TearDown(ctx)
}

// GetAllAssetsData collect tuning data for all the assets in the tenant
func (a *Adapter) GetAllAssetsData(ctx context.Context, tenantID string) ([]models.Attributes, error) {
	docs, err := a.getAllDocuments(ctx, tenantID)
	if err != nil {
		return []models.Attributes{}, err
	}

	policyVersion, err := a.getPolicyVersion(ctx, tenantID)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to get policy version, err: %v", err)
	}

	output := a.parseAllAssetsMongoAnswer(ctx, docs, policyVersion)
	return output, nil
}

// DeleteAllAssetsOfTenant deletes all documents associated with the given tenant
// This is done during the "init tenant" process
func (a *Adapter) DeleteAllAssetsOfTenant(ctx context.Context, tenantID string) error {
	filter := map[string]interface{}{
		"tuningId": primitive.Regex{
			Pattern: tenantID + "_*",
			Options: "i",
		},
	}

	allDocsOfTenant, err := a.getAllDocuments(ctx, tenantID)
	if err != nil {
		return errors.Wrapf(err, "failed to get all documents of tenant")
	}

	deleteCount, deleteErr := a.mdb.DeleteByQuery(ctx, filter)
	if deleteErr != nil {
		return errors.Wrapf(err, "error while deleting all documents of tenant")
	}

	if int64(len(allDocsOfTenant)) != deleteCount {
		return errors.Wrapf(err, "failed to delete all documents of tenant. Expected delete count: %d, but got: %d",
			len(allDocsOfTenant), deleteCount)
	}

	log.WithContext(ctx).WithEventID("966b7cb1-cbc0-4f40-8ab5-062f0351eba2").
		Debugf("Deleted all documents of tenant (count = %d)", deleteCount)

	return nil
}

func (a *Adapter) getAllDocuments(ctx context.Context, tenantID string) ([]document, error) {
	filter := map[string]interface{}{
		"tuningId": primitive.Regex{
			Pattern: tenantID + "_*",
			Options: "i",
		},
	}

	docs, err := a.runMongoQuery(ctx, filter)

	if err != nil {
		return []document{}, errors.Wrap(err, "failed to query mongo")
	}
	return docs, nil
}

func (a *Adapter) runMongoQuery(ctx context.Context, filter map[string]interface{}) ([]document, error) {
	opt, err := genQueryArgs(models.ReportAll)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate query for asset data")
	}

	var docs []document

	err = a.mdb.GetByQuery(ctx, filter, &docs, &opt)
	log.WithContext(ctx).Infof("mongo query res: %+v, err: %v", docs, err)
	return docs, err
}

func (a *Adapter) parseAllAssetsMongoAnswer(ctx context.Context, docs []document, policyVersion int64) []models.Attributes {
	if len(docs) == 0 {
		log.WithContext(ctx).Infof("Got empty result from mongo")
		return []models.Attributes{}
	}
	return a.fillAttributesSlice(ctx, docs, policyVersion)
}

func (a *Adapter) fillAttributesSlice(ctx context.Context, docs []document, policyVersion int64) []models.Attributes {
	output := make([]models.Attributes, 0)
	for i, doc := range docs {
		if doc.Attributes.PolicyVersion < policyVersion {
			continue
		}
		attr := *doc.Attributes
		log.WithContext(ctx).Infof("mongo query result number: %v, attributes: %+v", i, doc.Attributes)
		if attr.ApplicationUrls == "" || attr.Name == "" || attr.Type == "" {
			ids := strings.Split(doc.TuningID, "_")
			mgmtAsset, err := a.bc.GetMgmtAsset(ctx, ids[0], ids[1])
			if err == nil && isValidAsset(mgmtAsset) {
				attr.ApplicationUrls = fmt.Sprint(mgmtAsset.MainAttributes["applicationUrls"])
				attr.Name = mgmtAsset.Name
				attr.Type = mgmtAsset.AssetType
				attr.Family = mgmtAsset.Family
				err = a.ReportAsset(ctx, models.ReportAll, ids[0], ids[1], attr)
				if err != nil {
					log.WithContext(ctx).Warnf("failed to report data: %v, err: %v", attr, err)
					continue
				}
			} else {
				log.WithContext(ctx).Warnf("failed to restore data for asset: %v. err: %v, asset: %+v",
					ids[1], err, mgmtAsset)
				if !isValidDocument(doc) {
					log.WithContextAndEventID(ctx, "d2954e13-bfd1-4ca0-8e5d-c9d3f515f4a8").Errorf(
						"document %+v is corrupted", doc)
				}
				if errors.IsClass(err, errors.ClassUnauthorized) {
					err := a.deleteAsset(ctx, doc.TuningID)
					if err != nil {
						log.WithContext(ctx).Infof("failed to delete asset, err: %v", err)
					}
				}
				continue
			}
		}
		output = append(output, attr)
	}
	return output
}

func isValidDocument(doc document) bool {
	return doc.Attributes != nil &&
		doc.Attributes.Name != "" &&
		doc.Attributes.MgmtID != "" &&
		doc.Attributes.ApplicationUrls != "" &&
		doc.Attributes.Family != "" &&
		doc.Attributes.Type != ""
}

func isValidAsset(asset intel.Asset) bool {
	urls, ok := asset.MainAttributes["applicationUrls"]
	return ok && len(fmt.Sprint(urls)) > 0 &&
		len(asset.Name) > 0 &&
		len(asset.AssetType) > 0 &&
		len(asset.Family) > 0
}

func (a *Adapter) deleteAsset(ctx context.Context, tuningID string) error {
	filter := map[string]interface{}{
		"tuningId": tuningID,
	}

	log.WithContext(ctx).Infof("call delete for %v", tuningID)

	deleted, err := a.mdb.DeleteByQuery(ctx, filter)
	if err != nil {
		return errors.Wrapf(err, "failed to delete %v", tuningID)
	}
	if deleted == 0 {
		return errors.Errorf("asset %v not found", tuningID).SetClass(
			errors.ClassNotFound,
		)
	}
	return nil
}

func isAssetInAssetDetails(assets []models.AssetDetails, assetID string) bool {
	for _, asset := range assets {
		if asset.AssetID == assetID {
			return true
		}
	}
	return false
}

func shouldDeleteAsset(assets []models.AssetDetails, doc document, policyVersion int64) bool {
	return (doc.Attributes.PolicyVersion != 0 || doc.Attributes.ApplicationUrls == "") &&
		!isAssetInAssetDetails(assets, doc.Attributes.MgmtID) &&
		policyVersion > doc.Attributes.PolicyVersion+1
}

// PruneAssets deletes assets from DB that do not exist in assets argument
func (a *Adapter) PruneAssets(ctx context.Context, assets []models.AssetDetails, policyVersion int64) error {
	tenantID := fmt.Sprint(ctxutils.Extract(ctx, ctxutils.ContextKeyTenantID))
	a.reportPolicyVersion(ctx, tenantID, policyVersion)
	existingDocs, err := a.getAllDocuments(ctx, tenantID)
	log.WithContext(ctx).Debugf("pruning assets of tenant: %v", tenantID)
	if err != nil {
		return errors.Wrapf(err, "failed to get all assets for: %v", tenantID)
	}
	for _, existingDoc := range existingDocs {
		if shouldDeleteAsset(assets, existingDoc, policyVersion) {
			err = a.deleteAsset(ctx, existingDoc.TuningID)
			if err != nil {
				log.WithContext(ctx).Errorf("failed to delete asset from DB. err: %v", err)
				continue
			}
		} else {
			shouldUpdate := a.updateCertStatus(assets, existingDoc)

			if !shouldUpdate {
				continue
			}

			err = a.ReportAsset(ctx, models.ReportAll, tenantID, existingDoc.Attributes.MgmtID, *existingDoc.Attributes)
			if err != nil {
				log.WithContext(ctx).Warnf("failed to report asset: %v, err: %v", existingDoc.Attributes.MgmtID, err)
				continue
			}
		}
	}
	return nil
}

func (a *Adapter) getPolicyVersion(ctx context.Context, tenantID string) (int64, error) {
	filter := map[string]interface{}{
		"tenantId": tenantID,
	}
	opt := mongodb.QueryOptions{Projection: map[string]int{"policyVersion": 1, "tenantId": 1}}

	var docs []policyDocument

	err := a.mdb.GetByQuery(ctx, filter, &docs, &opt)
	log.WithContext(ctx).Infof("mongo query res: %+v, err: %v", docs, err)
	if err != nil {
		return 0, err
	}
	if len(docs) == 0 {
		return 0, nil
	}
	return docs[0].PolicyVersion, err
}

func (a *Adapter) reportPolicyVersion(ctx context.Context, tenantID string, policyVersion int64) {
	filter := map[string]interface{}{
		"tenantId": tenantID,
	}
	updateOp := mongodb.UpdateOperators{
		Set:         policyDocument{PolicyVersion: policyVersion},
		Unset:       nil,
		SetOnInsert: policyDocument{TenantID: tenantID},
		Push:        nil,
		Pull:        nil,
		AddToSet:    nil,
	}
	updateRes, err := a.mdb.UpdateOne(ctx, filter, updateOp, true)

	log.WithContext(ctx).Infof("call update once(%+v, %+v) = %+v, %+v", filter, updateOp, updateRes, err)

	if err != nil {
		log.WithContext(ctx).Warnf("failed to update document: %+v. err: %v", updateOp, err)
	}
}

func (a *Adapter) updateCertStatus(assets []models.AssetDetails, doc document) bool {
	shouldUpdate := false
	for _, asset := range assets {
		if doc.Attributes.MgmtID == asset.AssetID {
			if doc.Attributes.ApplicationUrls != asset.ApplicationUrls {
				for url := range doc.Attributes.CertInstallStatus {
					if url != "" && !strings.Contains(asset.ApplicationUrls, url) {
						delete(doc.Attributes.CertInstallStatus, url)
					}
				}
				shouldUpdate = true
			}
		}
	}
	return shouldUpdate
}

//func (a *Adapter) updateUpstreamStatus(assets []models.AssetDetails, doc document) bool {
//	shouldUpdate := false
//	for _, asset := range assets {
//		if doc.Attributes.MgmtID == asset.AssetID {
//			if doc.Attributes.ApplicationUrls != asset.ApplicationUrls {
//				for url := range doc.Attributes.UpstreamStatus {
//					if url != "" && !strings.Contains(asset.ApplicationUrls, url) {
//						delete(doc.Attributes.UpstreamStatus, url)
//					}
//				}
//				shouldUpdate = true
//			}
//		}
//	}
//	return shouldUpdate
//}
