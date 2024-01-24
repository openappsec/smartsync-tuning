//go:build wireinject
// +build wireinject

package ingector

import (
	"context"
	"database/sql/driver"

	"openappsec.io/jsonschema"
	"openappsec.io/mongodb"
	"openappsec.io/smartsync-tuning/internal/app/drivers/crdlistener"
	"openappsec.io/smartsync-tuning/internal/app/drivers/eventconsumer"
	"openappsec.io/smartsync-tuning/internal/app/drivers/scheduler"
	"openappsec.io/smartsync-tuning/internal/pkg/db/policy"
	"openappsec.io/smartsync-tuning/internal/pkg/db/sharedstorage"
	"openappsec.io/smartsync-tuning/internal/pkg/lock/redis"
	"openappsec.io/smartsync-tuning/internal/pkg/query/bqadapter"
	"openappsec.io/smartsync-tuning/internal/pkg/query/pg"

	tuningV1 "openappsec.io/smartsync-tuning/internal/app/tuningdomain/v1"
	tuningV2 "openappsec.io/smartsync-tuning/internal/app/tuningdomain/v2"
	"openappsec.io/smartsync-tuning/internal/pkg/db/intelligence"
	"openappsec.io/smartsync-tuning/internal/pkg/db/mongo"
	s3 "openappsec.io/smartsync-tuning/internal/pkg/db/s3"
	"openappsec.io/smartsync-tuning/internal/pkg/query"

	"openappsec.io/smartsync-tuning/internal/pkg/mgmt/graphql"
	mgmt "openappsec.io/smartsync-tuning/internal/pkg/mgmt/rest"

	"github.com/google/wire"
	"github.com/lib/pq"

	"openappsec.io/configuration"
	"openappsec.io/configuration/viper"
	"openappsec.io/health"
	kafka "openappsec.io/kafka/consumermanager"
	redisgo "openappsec.io/redis"
	"openappsec.io/smartsync-tuning/internal/app"
	"openappsec.io/smartsync-tuning/internal/app/drivers/http/rest"
)

// InitializeApp is an Adapter injector
func InitializeApp(ctx context.Context) (*app.App, error) {
	wire.Build(
		viper.NewViper,
		wire.Bind(new(configuration.Repository), new(*viper.Adapter)),

		configuration.NewConfigurationService,
		wire.Bind(new(rest.Configuration), new(*configuration.Service)),
		wire.Bind(new(app.Configuration), new(*configuration.Service)),
		wire.Bind(new(tuningV1.Configuration), new(*configuration.Service)),
		wire.Bind(new(tuningV2.Configuration), new(*configuration.Service)),
		wire.Bind(new(mgmt.Configuration), new(*configuration.Service)),
		wire.Bind(new(intelligence.Configuration), new(*configuration.Service)),
		wire.Bind(new(query.Configuration), new(*configuration.Service)),
		wire.Bind(new(s3.Configuration), new(*configuration.Service)),
		wire.Bind(new(graphql.Configuration), new(*configuration.Service)),
		wire.Bind(new(eventconsumer.Configuration), new(*configuration.Service)),
		wire.Bind(new(redis.Configuration), new(*configuration.Service)),
		wire.Bind(new(mongo.Configuration), new(*configuration.Service)),
		wire.Bind(new(bqadapter.Configuration), new(*configuration.Service)),
		//wire.Bind(new(crdlistener.Configuration), new(*configuration.Service)),

		tuningV1.NewTuningService,
		wire.Bind(new(rest.TuningService), new(*tuningV1.Tuning)),

		tuningV2.NewTuningService,
		wire.Bind(new(rest.TuningServiceV2), new(*tuningV2.Tuning)),
		wire.Bind(new(eventconsumer.AppService), new(*tuningV2.Tuning)),
		//wire.Bind(new(crdlistener.TuningAppService), new(*tuningV2.Tuning)),

		health.NewService,
		wire.Bind(new(rest.HealthService), new(*health.Service)),
		wire.Bind(new(app.HealthService), new(*health.Service)),

		// V1 Adapters
		jsonschema.NewJSONSchemaService,
		wire.Bind(new(rest.JSONSchemaValidator), new(*jsonschema.Service)),

		intelligence.NewAdapter,
		wire.Bind(new(app.Intelligence), new(*intelligence.Adapter)),
		wire.Bind(new(mongo.RepositoryBC), new(*intelligence.Adapter)),
		wire.Bind(new(tuningV2.CacheRepository), new(*intelligence.Adapter)),

		mongodb.NewClient,
		wire.Bind(new(mongo.DB), new(*mongodb.Mongo)),

		mongo.NewAdapter,
		wire.Bind(new(tuningV1.Repository), new(*mongo.Adapter)),
		wire.Bind(new(tuningV2.RepositoryV2), new(*mongo.Adapter)),
		wire.Bind(new(app.DBAdapter), new(*mongo.Adapter)),

		bqadapter.NewQueriesGenerator,
		wire.Bind(new(query.GenQueries), new(*bqadapter.GenBQQueries)),

		bqadapter.NewBQAdapter,
		wire.Bind(new(driver.Driver), new(*bqadapter.BQAdapter)),

		query.NewAdapter,
		wire.Bind(new(tuningV2.LogRepositoryAdapter), new(*query.Adapter)),
		wire.Bind(new(rest.TenantReportService), new(*query.Adapter)),

		redisgo.NewClient,
		wire.Bind(new(redis.Redis), new(*redisgo.Adapter)),

		redis.NewAdapter,
		wire.Bind(new(tuningV2.MultiplePodsLock), new(*redis.Adapter)),
		wire.Bind(new(app.DistLock), new(*redis.Adapter)),

		mgmt.NewAdapter,
		wire.Bind(new(tuningV1.Mgmt), new(*mgmt.Adapter)),

		graphql.NewAdapter,
		wire.Bind(new(tuningV2.PolicyDetails), new(*graphql.Adapter)),

		s3.NewAdapter,
		wire.Bind(new(tuningV2.S3Repo), new(*s3.Adapter)),
		wire.Bind(new(tuningV2.PolicyFetch), new(*s3.Adapter)),

		rest.NewAdapter,
		wire.Bind(new(app.RestAdapter), new(*rest.Adapter)),

		kafka.NewConsumerManager,
		wire.Bind(new(eventconsumer.ConsumerManager), new(*kafka.ConsumerManager)),

		eventconsumer.NewAdapter,
		wire.Bind(new(app.EventConsumerDriver), new(*eventconsumer.Adapter)),

		app.NewApp,
	)

	return &app.App{}, nil
}

// InitializeAppStandAlone is an Adapter injector
func InitializeAppStandAlone(ctx context.Context) (*app.StandAlone, error) {
	wire.Build(
		viper.NewViper,
		wire.Bind(new(configuration.Repository), new(*viper.Adapter)),

		configuration.NewConfigurationService,
		wire.Bind(new(rest.Configuration), new(*configuration.Service)),
		wire.Bind(new(app.Configuration), new(*configuration.Service)),
		wire.Bind(new(query.Configuration), new(*configuration.Service)),
		wire.Bind(new(pg.Configuration), new(*configuration.Service)),
		wire.Bind(new(sharedstorage.Configuration), new(*configuration.Service)),
		wire.Bind(new(s3.Configuration), new(*configuration.Service)),
		wire.Bind(new(tuningV2.Configuration), new(*configuration.Service)),
		wire.Bind(new(crdlistener.Configuration), new(*configuration.Service)),
		wire.Bind(new(scheduler.Configuration), new(*configuration.Service)),

		health.NewService,
		wire.Bind(new(rest.HealthService), new(*health.Service)),
		wire.Bind(new(app.HealthService), new(*health.Service)),

		sharedstorage.NewAdapter,
		wire.Bind(new(tuningV2.RepositoryV2), new(*sharedstorage.Adapter)),

		s3.NewAdapter,
		wire.Bind(new(tuningV2.S3Repo), new(*s3.Adapter)),

		crdlistener.NewReader,
		wire.Bind(new(tuningV2.PolicyFetch), new(*crdlistener.ReaderClient)),
		wire.Bind(new(tuningV2.PolicyDetails), new(*crdlistener.ReaderClient)),
		wire.Bind(new(crdlistener.ReaderInterface), new(*crdlistener.ReaderClient)),

		crdlistener.NewAdapter,
		wire.Bind(new(app.EventConsumerDriver), new(*crdlistener.Adapter)),

		tuningV2.NewStandAlone,
		wire.Bind(new(rest.StandaloneService), new(*tuningV2.StandAlone)),
		wire.Bind(new(crdlistener.TuningAppService), new(*tuningV2.StandAlone)),
		wire.Bind(new(scheduler.Service), new(*tuningV2.StandAlone)),

		pg.NewQueriesGen,
		wire.Bind(new(query.GenQueries), new(*pg.QueriesGen)),

		pg.NewPQDriver,
		wire.Bind(new(driver.Driver), new(*pq.Driver)),

		query.NewAdapter,
		wire.Bind(new(tuningV2.LogRepositoryAdapter), new(*query.Adapter)),

		rest.NewAdapterStandAlone,
		wire.Bind(new(app.RestAdapter), new(*rest.AdapterStandAlone)),

		scheduler.NewAdapter,
		wire.Bind(new(app.Scheduler), new(*scheduler.Adapter)),

		app.NewAppStandAlone,
	)

	return &app.StandAlone{}, nil
}

// InitializeAppStandAloneDocker is an Adapter injector
func InitializeAppStandAloneDocker(ctx context.Context) (*app.StandAlone, error) {
	wire.Build(
		viper.NewViper,
		wire.Bind(new(configuration.Repository), new(*viper.Adapter)),

		configuration.NewConfigurationService,
		wire.Bind(new(rest.Configuration), new(*configuration.Service)),
		wire.Bind(new(app.Configuration), new(*configuration.Service)),
		wire.Bind(new(query.Configuration), new(*configuration.Service)),
		wire.Bind(new(pg.Configuration), new(*configuration.Service)),
		wire.Bind(new(sharedstorage.Configuration), new(*configuration.Service)),
		wire.Bind(new(s3.Configuration), new(*configuration.Service)),
		wire.Bind(new(tuningV2.Configuration), new(*configuration.Service)),
		wire.Bind(new(scheduler.Configuration), new(*configuration.Service)),
		wire.Bind(new(policy.Configuration), new(*configuration.Service)),

		health.NewService,
		wire.Bind(new(rest.HealthService), new(*health.Service)),
		wire.Bind(new(app.HealthService), new(*health.Service)),

		sharedstorage.NewAdapter,
		wire.Bind(new(tuningV2.RepositoryV2), new(*sharedstorage.Adapter)),

		s3.NewAdapter,
		wire.Bind(new(tuningV2.S3Repo), new(*s3.Adapter)),

		policy.NewAdapter,
		wire.Bind(new(tuningV2.PolicyFetch), new(*policy.Adapter)),
		wire.Bind(new(tuningV2.PolicyDetails), new(*policy.Adapter)),

		eventconsumer.NewDockerAdapter,
		wire.Bind(new(app.EventConsumerDriver), new(*eventconsumer.DockerAdapter)),

		tuningV2.NewStandAlone,
		wire.Bind(new(rest.StandaloneService), new(*tuningV2.StandAlone)),
		wire.Bind(new(scheduler.Service), new(*tuningV2.StandAlone)),

		pg.NewQueriesGen,
		wire.Bind(new(query.GenQueries), new(*pg.QueriesGen)),

		pg.NewPQDriver,
		wire.Bind(new(driver.Driver), new(*pq.Driver)),

		query.NewAdapter,
		wire.Bind(new(tuningV2.LogRepositoryAdapter), new(*query.Adapter)),

		rest.NewAdapterStandAlone,
		wire.Bind(new(app.RestAdapter), new(*rest.AdapterStandAlone)),

		scheduler.NewAdapter,
		wire.Bind(new(app.Scheduler), new(*scheduler.Adapter)),

		app.NewAppStandAlone,
	)

	return &app.StandAlone{}, nil
}
