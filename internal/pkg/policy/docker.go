package policy

import (
	"context"
	"os"
	"strings"

	"openappsec.io/errors"
	"openappsec.io/log"
	"openappsec.io/smartsync-tuning/models"

	yaml "gopkg.in/yaml.v2"
)

const policyPath = "policy.path"

type rule struct {
	Mode           string
	Practices      []string
	TrustedSources string
}

type policy struct {
	Default       rule
	SpecificRules []rule
}

type policyFile struct {
	Policies       models.PolicySpec
	Practices      []models.PracticeSpec
	TrustedSources []models.TrustedSourcesSpec
}

type Adapter struct {
	policyPath string
}

type Configuration interface {
	GetString(key string) (string, error)
}

func NewAdapter(conf Configuration) (*Adapter, error) {
	path, err := conf.GetString(policyPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create docker policy adapter")
	}
	return &Adapter{policyPath: path}, nil
}

func (a *Adapter) GetPolicyDetails(ctx context.Context, tenantID string, assetID string,
	policyVersion int64) (models.AssetDetails, error) {
	assets, err := a.GetPolicy(ctx, tenantID, "", policyVersion)
	if err != nil {
		return models.AssetDetails{}, errors.Wrap(err, "failed to get policy")
	}
	for _, asset := range assets {
		if asset.AssetID == assetID {
			return asset, nil
		}
	}
	return models.AssetDetails{}, errors.New("asset not found").SetClass(errors.ClassNotFound)
}

func (a *Adapter) GetPolicy(ctx context.Context, tenantID string, path string,
	_ int64) ([]models.AssetDetails, error) {
	content := policyFile{}
	data, err := os.ReadFile(a.policyPath)
	if err != nil {
		return []models.AssetDetails{}, errors.Wrapf(err, "failed to read policy file. path: %v", a.policyPath)
	}

	err = yaml.Unmarshal(data, &content)
	if err != nil {
		return []models.AssetDetails{}, errors.Wrap(err, "failed to unmarshal policy file")
	}
	log.WithContext(ctx).Infof("unmarshal result: %+v", content)
	practicesID := content.Policies.DefaultPolicy.Practices
	if len(practicesID) != 1 {
		return nil, errors.New("multiple practices not supported")
	}
	practice, err := findPractice(content.Practices, practicesID[0])
	if err != nil {
		return []models.AssetDetails{}, errors.Wrapf(err, "failed to find practice (%v) of default asset",
			practicesID)
	}
	trustedSrcs, err := getTrusted(content.TrustedSources, content.Policies.DefaultPolicy.TrustedSources)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to find trusted sources for default asset")
		trustedSrcs = models.TrustedSourcesPolicy{}
	}
	defaultAsset := models.AssetDetails{
		AssetID:         "Any",
		TenantID:        "",
		PolicyVersion:   0,
		TrustedSources:  trustedSrcs,
		ApplicationUrls: "*",
		Name:            "",
		Type:            "",
		Mode:            convertMode(practice.OverrideMode, content.Policies.DefaultPolicy.Mode),
		Level:           strings.Title(practice.MinimumConfidence),
	}
	assets := []models.AssetDetails{defaultAsset}
	for _, rule := range content.Policies.SpecificRules {
		practice, err = findPractice(content.Practices, rule.Practices[0])
		if err != nil {
			log.WithContext(ctx).Warnf("Failed to find practice %s, err: %v", rule.Practices[0], err)
			continue
		}
		trustedSrcs, err = getTrusted(content.TrustedSources, rule.TrustedSources)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to find trusted sources for asset %v", rule.IngressRule)
			trustedSrcs = models.TrustedSourcesPolicy{}
		}
		assets = append(assets,
			models.AssetDetails{
				AssetID:         rule.IngressRule, // host
				TenantID:        "",
				PolicyVersion:   0,
				TrustedSources:  trustedSrcs,
				ApplicationUrls: rule.IngressRule,
				Name:            rule.IngressRule,
				Type:            "",
				Mode:            convertMode(practice.OverrideMode, rule.Mode),
				Level:           strings.Title(practice.MinimumConfidence),
			})
	}
	return assets, nil
}

func getTrusted(trustedSources []models.TrustedSourcesSpec, name string) (models.TrustedSourcesPolicy, error) {
	if len(name) == 0 {
		return models.TrustedSourcesPolicy{}, nil
	}
	for _, trustedSrc := range trustedSources {
		if name == trustedSrc.Name {
			identifiers := make([]models.Identifier, len(trustedSrc.SourcesIdentifiers))
			for i, identifier := range trustedSrc.SourcesIdentifiers {
				identifiers[i] = models.Identifier{Value: identifier}
			}
			return models.TrustedSourcesPolicy{
				NumOfSources:       trustedSrc.NumOfSources,
				SourcesIdentifiers: identifiers,
			}, nil
		}
	}
	return models.TrustedSourcesPolicy{}, errors.Errorf("resource %v not found", name)
}

func findPractice(practices []models.PracticeSpec, id string) (models.PracticeSpec, error) {
	for _, practice := range practices {
		if practice.Name == id {
			return practice, nil
		}
	}
	return models.PracticeSpec{}, errors.New("practice not found")
}

func convertMode(mode string, defaultMode string) string {
	switch mode {
	case "detect-learn":
		return "Detect"
	case "prevent-learn":
		return "Prevent"
	}
	return defaultMode
}

func (a *Adapter) GetPolicyVersion(ctx context.Context, tenantID string, userID string) (int, error) {
	return 0, nil
}

func (a *Adapter) GetTrustedSourcesPolicy(ctx context.Context, tenantID string, assetID string,
	resourceName string) (models.TrustedSourcesPolicy, error) {
	asset, err := a.GetPolicyDetails(ctx, tenantID, assetID, 0)
	if err != nil {
		return models.TrustedSourcesPolicy{}, err
	}
	return asset.TrustedSources, nil
}
