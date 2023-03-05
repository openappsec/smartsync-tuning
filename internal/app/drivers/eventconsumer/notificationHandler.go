package eventconsumer

import (
	"context"
	"encoding/json"

	"openappsec.io/ctxutils"

	"openappsec.io/errors"

	"openappsec.io/log"

	"openappsec.io/fog-msrv-waap-tuning-process/models"
)

const (
	notificationIDFirstRequest    = "a53a7091-5d7a-4881-9e64-0fa3a1fc5a93"
	notificationIDCertsStatus     = "4165c3b1-e9bc-44c3-888b-863e204c1bfb"
	notificationIDUpstreamsStatus = "46e5af4e-db29-444a-8f6b-2a6bd8f2e131"
)

type firstRequestData struct {
	AssetID               string `json:"assetId,omitempty"`
	OriginalEventSeverity string `json:"originalEventSeverity,omitempty"`
}

type installCertificateData struct {
	AssetID   string `json:"assetId,omitempty"`
	ProfileID string `json:"profileId,omitempty"`
	CertType  string `json:"certType,omitempty"`
	URL       string `json:"url,omitempty"`
	Message   string `json:"message,omitempty"`
}

type notificationData struct {
	Logs []struct {
		Log struct {
			EventSeverity string `json:"eventSeverity,omitempty"`
			EventSource   struct {
				TenantID string `json:"tenantId"`
				Version  string `json:"issuingEngineVersion"`
			} `json:"eventSource"`
			EventData struct {
				NotificationID string `json:"notificationId"`
				EventObject    struct {
					NotificationConsumerData struct {
						FirstRequestData firstRequestData       `json:"firstRequestNotificationConsumers,omitempty"`
						InstallCertData  installCertificateData `json:"certificationStatusNotificationConsumers,omitempty"`
						UpstreamData     models.UpstreamStatus  `json:"upstreamHealthcheckNotificationConsumers"`
					} `json:"notificationConsumerData"`
				} `json:"eventObject"`
			} `json:"eventData"`
		} `json:"log"`
	} `json:"logs"`
}

func (a *Adapter) handleFirstRequestNotification(ctx context.Context, data notificationData, i int) error {
	consumerData := data.Logs[i].Log.EventData.EventObject.NotificationConsumerData.FirstRequestData

	if len(consumerData.AssetID) == 0 || len(consumerData.OriginalEventSeverity) == 0 {
		log.WithContext(ctx).Infof("failed to extract asset ID or severity")
		return nil
	}

	firstRequest := models.FirstRequestNotification{
		Tenant:   data.Logs[i].Log.EventSource.TenantID,
		Asset:    consumerData.AssetID,
		Severity: consumerData.OriginalEventSeverity,
	}

	// call service to update
	return a.srv.UpdateFirstRequest(ctx, firstRequest)
}

func (a *Adapter) handleCertsStatusNotification(ctx context.Context, data notificationData, i int) error {
	consumerData := data.Logs[i].Log.EventData.EventObject.NotificationConsumerData.InstallCertData

	if len(consumerData.AssetID) == 0 {
		log.WithContext(ctx).Infof("missing asset ID in: %+v", consumerData)
		return nil
	}

	status := "Success"
	if data.Logs[i].Log.EventSeverity != "Info" {
		status = "Failure"
	}

	certsStatus := models.CertStatus{
		Tenant: data.Logs[i].Log.EventSource.TenantID,
		Asset:  consumerData.AssetID,
		Data: models.CertInstallStatus{
			CertType:  consumerData.CertType,
			ProfileID: consumerData.ProfileID,
			URL:       consumerData.URL,
			Status:    status,
			Message:   consumerData.Message,
		},
	}

	return a.srv.UpdateCertStatus(ctx, certsStatus)
}

func (a *Adapter) handleUpstreamsStatusNotification(ctx context.Context, data notificationData, i int) error {
	consumerData := data.Logs[i].Log.EventData.EventObject.NotificationConsumerData.UpstreamData

	if len(consumerData.Asset) == 0 {
		return errors.Errorf("missing asset id in: %+v", consumerData)
	}

	upstreamsStatus := models.UpstreamStatus{
		Tenant:  data.Logs[i].Log.EventSource.TenantID,
		Asset:   consumerData.Asset,
		Version: data.Logs[i].Log.EventSource.Version,
		Data: models.UpstreamHealthcheck{
			Agent:   consumerData.Data.Agent,
			Status:  consumerData.Data.Status,
			Message: consumerData.Data.Message,
		},
	}

	return a.srv.UpdateUpstreamStatus(ctx, upstreamsStatus)
}

func (a *Adapter) handleNotification(ctx context.Context, body []byte, headers map[string][]byte) error {
	ctx = a.headersToContextMiddleware(ctx, headers)
	log.WithContext(ctx).Infof("got notification")

	// extract notification data into FirstRequestNotification model
	var notifData notificationData
	err := json.Unmarshal(body, &notifData)
	if err != nil {
		log.WithContext(ctx).Infof("failed to unmarshal notification log: %v", string(body))
		return err
	}

	if len(notifData.Logs) == 0 {
		log.WithContext(ctx).Infof("failed to extracts logs from: %v", string(body))
		return errors.New("got empty notification body or fail to parse")
	}
	ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, notifData.Logs[0].Log.EventSource.TenantID)

	for i, notifLog := range notifData.Logs {
		switch notifLog.Log.EventData.NotificationID {
		case notificationIDFirstRequest:
			err = a.handleFirstRequestNotification(ctx, notifData, i)
		case notificationIDCertsStatus:
			err = a.handleCertsStatusNotification(ctx, notifData, i)
		case notificationIDUpstreamsStatus:
			err = a.handleUpstreamsStatusNotification(ctx, notifData, i)
		default:
			log.WithContext(ctx).Infof(
				"notification ID(%v) not supported",
				notifData.Logs[i].Log.EventData.NotificationID,
			)
			err = nil
		}
		if err != nil {
			log.WithContext(ctx).Warnf(
				"notification handler returned the following error for notification ID(%v): %v",
				notifData.Logs[i].Log.EventData.NotificationID, err,
			)
			return err
		}
	}
	return nil
}
