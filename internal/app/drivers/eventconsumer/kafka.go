package eventconsumer

import (
	"context"
	"fmt"

	"gopkg.in/go-playground/validator.v9"

	"openappsec.io/log"

	"openappsec.io/fog-msrv-waap-tuning-process/models"
	"openappsec.io/ctxutils"
	"openappsec.io/errors"
	"openappsec.io/kafka"

	"github.com/google/uuid"
)

const (
	k8sNamespace                 = "K8S_NAMESPACE"
	kafkaConfBaseKey             = "kafka"
	kafkaConsumerConfKey         = kafkaConfBaseKey + ".consumer"
	kafkaConsumerTLSConfKey      = kafkaConsumerConfKey + ".tls"
	kafkaConsumerBrokersConfKey  = kafkaConsumerConfKey + ".brokers"
	kafkaConsumerDLQTopicConfKey = kafkaConsumerConfKey + ".dlq.topic"

	learnNotificationConfBaseKey            = kafkaConsumerConfKey + ".learnNotification"
	learnNotificationConsumerTopicConfKey   = learnNotificationConfBaseKey + ".topic"
	learnNotificationConsumerGroupIDConfKey = learnNotificationConfBaseKey + ".groupId"

	processTableConfBaseKey            = kafkaConsumerConfKey + ".processTable"
	processTableConsumerTopicConfKey   = processTableConfBaseKey + ".topic"
	processTableConsumerGroupIDConfKey = processTableConfBaseKey + ".groupId"

	installPolicyGEMConfBaseKey            = kafkaConsumerConfKey + ".policyNotification"
	installPolicyGEMConsumerTopicConfKey   = installPolicyGEMConfBaseKey + ".topic"
	installPolicyGEMConsumerGroupIDConfKey = installPolicyGEMConfBaseKey + ".groupId"

	initTenantConfBaseKey            = kafkaConsumerConfKey + ".initTenant"
	initTenantConsumerTopicConfKey   = initTenantConfBaseKey + ".topic"
	initTenantConsumerGroupIDConfKey = initTenantConfBaseKey + ".groupId"

	revokeAgentConfBaseKey            = kafkaConsumerConfKey + ".revokeAgent"
	revokeAgentConsumerTopicConfKey   = revokeAgentConfBaseKey + ".topic"
	revokeAgentConsumerGroupIDConfKey = revokeAgentConfBaseKey + ".groupId"

	tenantEventTypeInitTenant = "initTenant"

	eventTypeHeaderKey = "eventType"
	eventTraceIDKey    = "eventTraceId"
	tenantIDHeaderKey  = "tenantId"
)

// mockgen -package mocks -source ./internal/app/drivers/eventconsumer/kafka.go -mock_names Configuration=MockKafkaConsumerConfiguration -destination ./mocks/mock_kafkaConsumer.go
// mockgen -destination mocks/mock_kafkaConsumer.go -package mocks -source=./internal/app/drivers/eventconsumer/kafka.go -mock_names Configuration=MockKafkaConsumerConfiguration

// ConsumerManager exposes the interface for managing kafka consumers
type ConsumerManager interface {
	Add(ctx context.Context, kafkaConfiguration kafka.ConsumerConfig, f kafka.HandleFunc) error
	Run(ctx context.Context)
	HealthCheck(ctx context.Context) (string, error)
	TearDown() error
}

// Configuration exposes an interface of configuration related actions
type Configuration interface {
	GetString(key string) (string, error)
	GetBool(key string) (bool, error)
}

// AppService exposes the domain interface for handling events
type AppService interface {
	UpdateFirstRequest(ctx context.Context, firstRequestData models.FirstRequestNotification) error
	UpdateCertStatus(ctx context.Context, certStatus models.CertStatus) error
	UpdateUpstreamStatus(ctx context.Context, upstreamStatus models.UpstreamStatus) error
	UpdatePolicy(ctx context.Context, msg models.PolicyMessageData) error
	ProcessTable(ctx context.Context, tenantData models.ProcessTenantNotification) error
	InitTenant(ctx context.Context, tenantID string) error
	RevokeAgent(ctx context.Context, agent models.RevokeAgent) error
}

// Adapter kafka adapter
type Adapter struct {
	cm        ConsumerManager
	srv       AppService
	validator *validator.Validate
}

// NewAdapter creates and register consumer for kafka events
func NewAdapter(cm ConsumerManager, srv AppService, conf Configuration) (*Adapter, error) {
	brokers, err := conf.GetString(kafkaConsumerBrokersConfKey)
	if err != nil {
		return nil, err
	}

	tls, err := conf.GetBool(kafkaConsumerTLSConfKey)
	if err != nil {
		return nil, err
	}

	dlqTopic, err := conf.GetString(kafkaConsumerDLQTopicConfKey)
	if err != nil {
		return nil, err
	}

	topicPrefix, err := conf.GetString(k8sNamespace)
	if err != nil {
		log.Warnf("failed to get k8s namespace")
		topicPrefix = ""
	} else {
		topicPrefix += "_"
	}

	learnNotificationTopic, err := conf.GetString(learnNotificationConsumerTopicConfKey)
	if err != nil {
		return nil, err
	}

	learnNotificationGroupID, err := conf.GetString(learnNotificationConsumerGroupIDConfKey)
	if err != nil {
		return nil, err
	}

	learnNotificationConfig := kafka.ConsumerConfig{
		Brokers: brokers,
		TLS:     tls,
		Topic:   topicPrefix + learnNotificationTopic,
		GroupID: fmt.Sprintf("%s-%s", topicPrefix, learnNotificationGroupID),
		RetryPolicy: &kafka.RetryPolicy{
			MaxAttempts: 5,
			DLQTopic:    dlqTopic,
		},
		CommitAfterHandlingMsg: true,
	}

	processTableTopic, err := conf.GetString(processTableConsumerTopicConfKey)
	if err != nil {
		return nil, err
	}

	processTableGroupID, err := conf.GetString(processTableConsumerGroupIDConfKey)
	if err != nil {
		return nil, err
	}

	processTableConfig := kafka.ConsumerConfig{
		Brokers: brokers,
		TLS:     tls,
		Topic:   topicPrefix + processTableTopic,
		GroupID: fmt.Sprintf("%s-%s", topicPrefix, processTableGroupID),
		RetryPolicy: &kafka.RetryPolicy{
			MaxAttempts: 5,
			DLQTopic:    dlqTopic,
		},
		CommitAfterHandlingMsg: false,
	}

	installPolicyGEMTopic, err := conf.GetString(installPolicyGEMConsumerTopicConfKey)
	if err != nil {
		return nil, err
	}
	installPolicyGEMGroupID, err := conf.GetString(installPolicyGEMConsumerGroupIDConfKey)
	if err != nil {
		return nil, err
	}

	cConfPolicyGEMMQ := kafka.ConsumerConfig{
		Brokers: brokers,
		Topic:   topicPrefix + installPolicyGEMTopic,
		GroupID: fmt.Sprintf("%s-%s", topicPrefix, installPolicyGEMGroupID),
		TLS:     tls,
		RetryPolicy: &kafka.RetryPolicy{
			MaxAttempts: 5,
			DLQTopic:    dlqTopic,
		},
		CommitAfterHandlingMsg: true,
	}

	initTenantTopic, err := conf.GetString(initTenantConsumerTopicConfKey)
	if err != nil {
		return nil, err
	}
	initTenantGroupID, err := conf.GetString(initTenantConsumerGroupIDConfKey)
	if err != nil {
		return nil, err
	}

	initTenantConfig := kafka.ConsumerConfig{
		Brokers: brokers,
		Topic:   topicPrefix + initTenantTopic,
		GroupID: fmt.Sprintf("%s-%s", topicPrefix, initTenantGroupID),
		TLS:     tls,
		RetryPolicy: &kafka.RetryPolicy{
			MaxAttempts: 5,
			DLQTopic:    dlqTopic,
		},
		CommitAfterHandlingMsg: true,
	}

	revokeAgentTopic, err := conf.GetString(revokeAgentConsumerTopicConfKey)
	if err != nil {
		return nil, err
	}

	revokeAgentGroupID, err := conf.GetString(revokeAgentConsumerGroupIDConfKey)
	if err != nil {
		return nil, err
	}

	consumerConfRevokeAgent := kafka.ConsumerConfig{
		Brokers: brokers,
		Topic:   revokeAgentTopic,
		GroupID: revokeAgentGroupID,
		TLS:     tls,
		RetryPolicy: &kafka.RetryPolicy{
			MaxAttempts: 5,
			DLQTopic:    dlqTopic,
		},
		CommitAfterHandlingMsg: true,
	}

	a := &Adapter{cm: cm, srv: srv, validator: validator.New()}

	if err := cm.Add(context.Background(), learnNotificationConfig, a.handleNotification); err != nil {
		return nil, errors.Wrap(err, "Failed to add first request consumer")
	}
	if err := cm.Add(context.Background(), processTableConfig, a.handleProcessTable); err != nil {
		return nil, errors.Wrap(err, "Failed to add process table consumer")
	}
	if err := cm.Add(context.Background(), cConfPolicyGEMMQ, a.handlePolicy); err != nil {
		return nil, errors.Wrap(err, "Failed to add policy consumer")
	}
	if err := cm.Add(context.Background(), initTenantConfig, a.handleInitTenant); err != nil {
		return nil, errors.Wrap(err, "Failed to add init tenant consumer")
	}
	if err := cm.Add(context.Background(), consumerConfRevokeAgent, a.handleRevokeAgent); err != nil {
		return nil, errors.Wrap(err, "Failed to add revoke agent consumer")
	}

	return a, nil
}

func (a *Adapter) headersToContextMiddleware(ctx context.Context, headers map[string][]byte) context.Context {
	var eventTraceID string
	rawEventTraceID, ok := headers[eventTraceIDKey]
	if ok {
		eventTraceID = string(rawEventTraceID)
	} else {
		eventTraceID = uuid.New().String()
	}

	tenantID, ok := headers[tenantIDHeaderKey]
	if !ok || len(tenantID) == 0 {
		log.WithContext(ctx).Warnf("missing tenant id header in: %v", headers)
	} else {
		ctx = ctxutils.Insert(ctx, ctxutils.ContextKeyTenantID, string(tenantID))
	}

	return ctxutils.Insert(ctx, ctxutils.ContextKeyEventTraceID, eventTraceID)
}

// createStringHeaders converts kafka message headers from byte slice to string
func createStringHeaders(headers map[string][]byte) map[string]string {
	ret := make(map[string]string)
	for k, v := range headers {
		ret[k] = string(v)
	}

	return ret
}

// HealthCheck checks adapter health
func (a *Adapter) HealthCheck(ctx context.Context) (string, error) {
	return a.cm.HealthCheck(ctx)
}

// Start running the consumers
func (a *Adapter) Start(ctx context.Context) {
	log.WithContext(ctx).Infof("event consumer is running")
	a.cm.Run(ctx)
}

// Stop stopping the consumers
func (a *Adapter) Stop(ctx context.Context) error {
	log.WithContext(ctx).Infof("stopping event consumer")
	if err := a.cm.TearDown(); err != nil {
		return errors.Wrap(err, "Failed to gracefully stop message queues")
	}

	return nil
}
