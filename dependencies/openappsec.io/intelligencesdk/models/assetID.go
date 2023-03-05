package models

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"openappsec.io/errors"
)

const (
	separator = ";;;"
)

// CalculateIDLegacy create an asset ID for Legacy API from the main attributes field inside asset struct
func (a Asset) CalculateIDLegacy() (string, error) {
	id, err := json.Marshal(a.MainAttributes)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to marshal asset main attributes for main attributes: (%+v)", a.MainAttributes).SetClass(errors.ClassInternal)
	}

	sum := sha256.Sum256(id)
	return hex.EncodeToString(sum[:]), nil
}

// CalculateAssetID create an asset ID using base64 returns only the reversible asset id
func (a Asset) CalculateAssetID() (string, error) {
	if len(a.MainAttributes) <= 0 {
		return "", errors.Errorf("Failed to calculate asset ID since MainAttributes are missing").SetClass(errors.ClassInternal)
	}

	bMainAttr, err := json.Marshal(a.MainAttributes)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to marshal asset MainAttributes (%+v)", a.MainAttributes).SetClass(errors.ClassInternal)
	}

	assetIDStr := fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", a.ObjectType, separator,
		a.Class, separator, a.Category, separator, a.Family, separator, a.Group, separator, a.Order, separator, a.Kind, separator, string(bMainAttr))
	id := b64.URLEncoding.EncodeToString([]byte(assetIDStr))
	return id, nil
}

// CalculateID create an asset ID using base64
func (a Asset) CalculateID() (string, string, error) {
	// This is a legacy asset we got from the repo in an API V2 request
	if a.AssetID != "" && a.AssetID == a.AssetIDReversible {
		id, err := a.CalculateIDLegacy()
		if err != nil {
			return "", "", err
		}

		return id, id, nil
	}

	id, err := a.CalculateAssetID()
	if err != nil {
		return "", "", err
	}

	sum := sha256.Sum256([]byte(id))
	idSha := hex.EncodeToString(sum[:])
	return id, idSha, nil
}

// ReversibleAssetIDToAssetID excepts a reversible asset ID and returns an asset ID
func ReversibleAssetIDToAssetID(assetID string) string {
	sum := sha256.Sum256([]byte(assetID))
	idSha := hex.EncodeToString(sum[:])
	return idSha
}

// ConvertAssetIDToAsset gets an assetID and reverse it back to asset.
func ConvertAssetIDToAsset(assetID string) (Asset, error) {
	decodedAssetID, err := b64.URLEncoding.DecodeString(assetID)
	if err != nil {
		return Asset{}, errors.Wrapf(err, "Failed to decode assetID: %s", assetID)
	}

	splitVal := strings.Split(string(decodedAssetID), separator)
	if len(splitVal) < 8 || !IsValidObjectType(splitVal[0]) {
		return Asset{}, errors.Errorf("Failed to reverse the assetID, expected format: "+
			"objectType;;;class;;;category;;;family;;;group;;;order;;;kind;;;mainAttr, given: %s", decodedAssetID)
	}

	var mainAttr MainAttributes
	if err := json.Unmarshal([]byte(splitVal[7]), &mainAttr); err != nil {
		return Asset{}, errors.Wrapf(err, "Failed to unmarshal the asset mainAttributes (%s) from the assetID", splitVal[7])
	}

	return Asset{
		ObjectType:     ObjectType(splitVal[0]),
		Class:          splitVal[1],
		Category:       splitVal[2],
		Family:         splitVal[3],
		Group:          splitVal[4],
		Order:          splitVal[5],
		Kind:           splitVal[6],
		MainAttributes: mainAttr,
		AssetID:        assetID,
	}, nil
}

// GetAssetID gets the assetID field or calculates it. It returns an error in case it failed to calculate the ID.
// It doesn't change the underlying asset
func (a Asset) GetAssetID(ctx context.Context) (string, string, error) {
	astID := a.AssetID
	astIDSha := ""
	apiV, err := GetAPIVersionFromContext(ctx)
	if err != nil {
		return "", "", errors.Wrapf(err, "Failed to get API version from context")
	}

	if apiV == APILegacy {
		astID, err = a.CalculateIDLegacy()
		astIDSha = astID
	} else {
		astID, astIDSha, err = a.CalculateID()
	}

	if err != nil {
		return "", "", errors.Wrapf(err, "Failed calculate asset id for api %s for asset %+v", apiV, a.Diet())
	}

	return astID, astIDSha, nil
}

// GetAssetsIds gets the assetID field or calculates it for each asset.
// It returns an error in case it failed to calculate one of the IDs.
func (a Assets) GetAssetsIds(ctx context.Context) ([]string, []string, error) {
	ids := make([]string, 0, len(a))
	idsSha := make([]string, 0, len(a))
	for _, asset := range a {
		id, idSha, err := asset.GetAssetID(ctx)
		if err != nil {
			return []string{}, []string{}, errors.Wrapf(err, "Failed to calculates the assets ids")
		}

		ids = append(ids, id)
		idsSha = append(idsSha, idSha)
	}

	return ids, idsSha, nil
}

// ValidateAssetID that the given assetID matches the asset
func (a Asset) ValidateAssetID(ctx context.Context, got string) error {
	apiV, err := GetAPIVersionFromContext(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed to get API version from context")
	}

	if apiV == APILegacy {
		return a.validateLegacyID(got)
	}

	want, _, err := a.CalculateID()
	if err != nil {
		return errors.Wrap(err, "Failed to create asset ID from asset struct")
	}

	if got != want {
		return errors.Errorf("AssetID (%s) does not match the asset ID (%s)", got, want).SetClass(errors.ClassBadInput)
	}

	return nil
}

// validateLegacyID validates that the given assetID is valid according to LEGACY API
func (a *Asset) validateLegacyID(got string) error {
	want, err := a.CalculateIDLegacy()
	if err != nil {
		return errors.Wrap(err, "Failed to create legacy asset ID from asset struct")
	}

	if got != want {
		return errors.Errorf("AssetID (%s) does not match %s (sha256(%+v) = %s)", got, FieldMainAttributes, a.MainAttributes, want).SetClass(errors.ClassBadInput)
	}

	return nil
}
