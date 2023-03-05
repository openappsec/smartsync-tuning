package eventconsumer

import (
	"context"
	"encoding/json"

	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/log"
)

// InitTenantMessageBody defines the body of the init tenant message queue message
type InitTenantMessageBody struct {
	TenantID string `json:"tenantId" validate:"required"`
}

// handleInitTenant handles the init tenant process
func (a *Adapter) handleInitTenant(ctx context.Context, body []byte, headers map[string][]byte) error {
	ctx = a.headersToContextMiddleware(ctx, headers)
	eventType, ok := headers[eventTypeHeaderKey]
	if !ok {
		return errors.Errorf("Tenant event message are missing event type header").SetClass(errors.ClassBadInput)
	}

	strEventType := string(eventType)
	if strEventType != tenantEventTypeInitTenant {
		log.WithContext(ctx).WithEventID("1fe0c12a-abd4-43cd-903c-911a77f2bab1").
			Debugf("Got unknown event type %s, skipping..", strEventType)
		return nil
	}

	infoLogFields := log.Fields{
		"headers": createStringHeaders(headers),
		"body":    string(body),
	}

	log.WithContextAndFields(ctx, infoLogFields).WithEventID("88f85a97-90a5-4740-afb8-d31244c34c37").
		Infof("Consumer received new tenant event message (event type = %s)", strEventType)

	var initTenantMessageBody InitTenantMessageBody
	if err := json.Unmarshal(body, &initTenantMessageBody); err != nil {
		log.WithContext(ctx).WithEventID("f28771bf-1be3-4061-a306-d63b139cc5b0").
			Errorf("Failed to unmarshall message body to InitTenantMessageBody struct. Error: %v", err)
		return errors.Wrapf(err, "Failed to unmarshal message body to InitTenantMessageBody struct").SetClass(errors.ClassBadInput)
	}

	if errs := a.validator.Struct(initTenantMessageBody); errs != nil {
		log.WithContext(ctx).WithEventID("8581a1d6-7977-4378-805c-2ca84c9873f8").
			Errorf("invalid init tenant message body: errs: %v, body: %.512v", errs, string(body))
		return errors.Errorf("invalid init tenant message body: errs: %v, body: %.512v...", errs, string(body))
	}

	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, initTenantMessageBody.TenantID)
	if err := a.srv.InitTenant(ctx, initTenantMessageBody.TenantID); err != nil {
		log.WithContext(ctx).WithEventID("021af13b-02c7-4558-9edb-7dd604b05334").
			Errorf("failed to init tenant. Error: %+v", err)
		return errors.Wrapf(err, "Failed to init tenant")
	}

	log.WithContext(ctx).WithEventID("b76f9f9b-0801-4bbc-980a-8842638af569").
		Infof("Successfully handled init tenant message")

	return nil
}
