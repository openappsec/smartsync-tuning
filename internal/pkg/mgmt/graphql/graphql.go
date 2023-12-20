package graphql

import (
	"context"
	"net/url"

	"github.com/hashicorp/go-uuid"

	"openappsec.io/smartsync-tuning/models"

	"github.com/machinebox/graphql"
	"openappsec.io/errors"
	"openappsec.io/log"
)

const (
	confKeyMGraphqlBase = "graphql"
	confKeyMGraphqlHost = confKeyMGraphqlBase + ".host"
)

// SourcesIdentifier for trustedSources
type SourcesIdentifier struct {
	Source string
}

type trustedSources struct {
	GetParameters []struct {
		ID                 string
		NumOfSources       int
		SourcesIdentifiers []SourcesIdentifier
	}
}

// Parameters Id for specific asset
type Parameters struct {
	ID string
}

type getAssetByID struct {
	GetAsset struct {
		Name       string
		Parameters []Parameters
	}
}

// policy struct to get policy version
type policyDetails struct {
	GetPolicy struct {
		ID       string
		TenantID string
		Version  int
	}
}

// Configuration used to get the configuration of the management hosts
type Configuration interface {
	GetString(key string) (string, error)
}

// Adapter for GraphQL
type Adapter struct {
	conf      Configuration
	graphHost string
	userID    string
}

// NewAdapter creates new adapter
func NewAdapter(c Configuration) (*Adapter, error) {
	a := &Adapter{conf: c}
	id, err := uuid.GenerateUUID()
	if err == nil {
		a.userID = id
	}
	if err := a.initialize(); err != nil {
		return &Adapter{}, errors.Wrap(err, "failed to initialize MGMT rest adapter")
	}
	return a, nil
}

// initialize the adapter
func (a *Adapter) initialize() error {
	host, err := a.conf.GetString(confKeyMGraphqlHost)
	if err != nil {
		return errors.Wrapf(err, "failed to get mgmt policy baseURL from %v", confKeyMGraphqlHost)
	}
	if _, err = url.Parse(host); err != nil {
		return err
	}
	a.graphHost = host

	return nil
}

// GetPolicyVersion from graphql
func (a *Adapter) GetPolicyVersion(ctx context.Context, tenantID string, userID string) (int, error) {
	log.WithContext(ctx).Debugf("Get Policy version for tenantID %s and userID %s", tenantID, userID)
	respData, err := a.getPolicy(ctx, tenantID, userID)
	if err != nil {
		return 0, err
	}

	return respData.GetPolicy.Version, nil
}

func (a *Adapter) getPolicy(ctx context.Context, tenantID string, userID string) (policyDetails, error) {

	client := graphql.NewClient(a.graphHost)
	// get policy query
	req := graphql.NewRequest(`query { getPolicy { id tenantId version}}`)

	// set header fields
	req.Header.Set("x-user-id", userID)
	req.Header.Set("x-tenant-id", tenantID)

	// define a Context for the request
	var respData policyDetails

	if err := client.Run(ctx, req, &respData); err != nil {
		return policyDetails{}, errors.Wrap(err, "Failed to get policy version from Graphql")
	}
	return respData, nil
}

// GetTrustedSourcesParameters get trusted sources parameters details
func (a *Adapter) getTrustedSourcesParameters(ctx context.Context, tenantID, userID, assetID string) (trustedSources, error) {
	log.WithContext(ctx).Infof("Get Trusted sources parameters for tenantID %s and userID %s", tenantID, userID)

	client := graphql.NewClient(a.graphHost)

	req := graphql.NewRequest(`
		query {
			getParameters(includePrivateParameters: true){
			  ...on TrustedSourceParameter {
				id
				numOfSources
				sourcesIdentifiers {
				  id
				  source
				}
			  }
			}
		}
	`)

	// set header fields
	req.Header.Set("x-user-id", userID)
	req.Header.Set("x-tenant-id", tenantID)

	var respData trustedSources

	if err := client.Run(ctx, req, &respData); err != nil {
		return trustedSources{}, errors.Wrap(err, "Failed to get trusted sources parameters from Graphql")
	}

	return respData, nil
}

// GetAssetParametersByID get asset parameters id for specific asset
func (a *Adapter) getAssetParametersByID(ctx context.Context, tenantID, userID, assetID string) (getAssetByID, error) {
	log.WithContext(ctx).Infof("Get asset details by ID for tenantID %s and userID %s", tenantID, userID)

	client := graphql.NewClient(a.graphHost)

	req := graphql.NewRequest(`
		query ($id: String!) {
			getAsset (id:$id) {
				name
				parameters {
					id
				}
			}
		}
	`)

	// set any variables
	req.Var("id", assetID)

	// set header fields
	req.Header.Set("x-user-id", userID)
	req.Header.Set("x-tenant-id", tenantID)

	var respData getAssetByID

	if err := client.Run(ctx, req, &respData); err != nil {
		return getAssetByID{}, errors.Wrap(err, "Failed to get asset details by ID from Graphql")
	}

	return respData, nil
}

// GetTrustedSourcesPolicy get trusted sources policy
func (a *Adapter) GetTrustedSourcesPolicy(ctx context.Context, tenantID, assetID, userID string) (models.TrustedSourcesPolicy, error) {
	log.Debugf("Get trusted sources policy for tenantID %s and userID %s", tenantID, userID)
	var result models.TrustedSourcesPolicy
	parameters, err := a.getTrustedSourcesParameters(ctx, tenantID, userID, assetID)
	if err != nil {
		return models.TrustedSourcesPolicy{}, errors.Wrap(err, "Failed to get trusted sources parameters from Graphql")
	}
	parametersAsset, _ := a.getAssetParametersByID(ctx, tenantID, userID, assetID)
	if err != nil {
		return models.TrustedSourcesPolicy{}, errors.Wrap(err, "Failed to get asset details by ID from Graphql")
	}

	assetParameters := parametersAsset.GetAsset.Parameters
	trustedSourcesParameters := parameters.GetParameters

	for _, assetParam := range assetParameters {
		for _, tsParam := range trustedSourcesParameters {
			if tsParam.ID == assetParam.ID {
				result.NumOfSources = tsParam.NumOfSources
				for _, si := range tsParam.SourcesIdentifiers {
					var identifier models.Identifier
					identifier.Value = si.Source
					result.SourcesIdentifiers = append(result.SourcesIdentifiers, identifier)
				}
			}
		}
	}

	log.WithContext(ctx).Infof("GetTrustedSourcesPolicy results processing: %v", result)
	return result, nil
}
