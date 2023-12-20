package eventconsumer

import (
	"context"
	"encoding/json"

	"openappsec.io/smartsync-tuning/models"

	"openappsec.io/log"

	"openappsec.io/errors"
)

func (a *Adapter) handleProcessTable(_ context.Context, body []byte, headers map[string][]byte) error {
	ctx := context.Background()
	ctx = a.headersToContextMiddleware(ctx, headers)
	// extract notification data into string
	log.WithContext(ctx).Infof("handling process tenant event")
	if len(body) == 0 {
		return errors.New("got empty notification")
	}

	var processTenant models.ProcessTenantNotification
	err := json.Unmarshal(body, &processTenant)

	if err != nil {
		return errors.Wrapf(err, "failed to unmarshal body %v", string(body))
	}

	if processTenant.TenantID == "" || len(processTenant.Assets) == 0 {
		return errors.New("failed to extract data from json: " + string(body))
	}

	for _, asset := range processTenant.Assets {
		if asset.MgmtID == "" {
			log.WithContext(ctx).Errorf("missing MGMT ID for asset in tenant: %v", processTenant.TenantID)
			return errors.Errorf("failed to extract asset IDs data from json: %v for tenant: %v", string(body),
				processTenant.TenantID)
		}
	}

	go func() {
		err := a.srv.ProcessTable(ctx, processTenant)
		if err != nil {
			log.Errorf("failed to process table: %v, error: %v", processTenant, err)
		}
	}()
	return nil
}
