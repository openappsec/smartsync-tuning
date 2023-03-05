package eventconsumer

import (
	"context"
	"encoding/json"

	"openappsec.io/fog-msrv-waap-tuning-process/models"
	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/log"
)

func (a *Adapter) handlePolicy(ctx context.Context, body []byte, headers map[string][]byte) error {
	ctx = a.headersToContextMiddleware(ctx, headers)
	log.WithContext(ctx).Infof("Consumer received new install policy GEM message")
	var policyMsg models.PolicyMessageData

	if err := json.Unmarshal(body, &policyMsg); err != nil {
		log.WithContext(ctx).Errorf("Failed to unmarshal kafka install policy GEM message. Error: %s", err)
		return nil
	}

	if errs := a.validator.Struct(policyMsg); errs != nil {
		log.WithContext(ctx).Errorf("invalid json: errs: %v, body: %.512v", errs, string(body))
		return errors.Errorf("invalid json: errs: %v, body: %.512v...", errs, string(body))
	}

	log.WithContext(ctx).Debugf("policy unmarshall: extracted: %+v, json: %.512v...", policyMsg, string(body))

	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, policyMsg.TenantID)

	// call service to update
	go func() {
		err := a.srv.UpdatePolicy(ctx, policyMsg)
		if err != nil {
			log.WithContext(ctx).Errorf(
				"Failed to update policy after consuming kafka install policy GEM message. Error: %s", err,
			)
		}
	}()

	return nil
}
