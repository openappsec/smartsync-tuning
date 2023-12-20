package eventconsumer

import (
	"context"
	"encoding/json"

	"openappsec.io/smartsync-tuning/models"
	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/log"
)

type revokeAgentMQMessageBody struct {
	ProfileID string `json:"profileId" validate:"required"`
	AgentID   string `json:"agentId" validate:"required"`
}

func (a *Adapter) handleRevokeAgent(ctx context.Context, body []byte, headers map[string][]byte) error {
	ctx = a.headersToContextMiddleware(ctx, headers)
	log.WithContext(ctx).Infof("handle revoke agent event: %v", string(body))
	var revokeAgentMessageBody revokeAgentMQMessageBody
	if err := json.Unmarshal(body, &revokeAgentMessageBody); err != nil {
		log.WithContext(ctx).WithEventID("d647d55a-6189-4a48-9ca6-1c1762ddf62e").
			Errorf("Failed to unmarshal message body to revokeAgentMQMessageBody struct. Error: %v", err)
		return errors.Wrapf(err,
			"Failed to unmarshal message body to revokeAgentMQMessageBody struct").SetClass(errors.ClassBadInput)
	}

	tenantID := ctxutils.ExtractString(ctx, ctxutils.ContextKeyTenantID)
	agentID := revokeAgentMessageBody.AgentID
	profileID := revokeAgentMessageBody.ProfileID
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyAgentID, agentID)
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyProfileID, profileID)

	if tenantID == "" {
		return errors.New("failed to extract tenant id")
	}

	revokeAgent := models.RevokeAgent{
		TenantID: tenantID,
		AgentID:  agentID,
	}

	log.WithContext(ctx).WithEventID("3609384d-13c0-4740-a4cb-197a0220a234").Infof(
		"calling revoke agent: %+v", revokeAgent)

	err := a.srv.RevokeAgent(ctx, revokeAgent)

	log.WithContext(ctx).WithEventID("63c6c406-0ee8-4056-a160-303e9e918d07").Infof(
		"revoke agent: %+v return error: %v", revokeAgent, err)

	return err
}
