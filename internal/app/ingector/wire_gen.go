// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package ingector

import (
	"context"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/app"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/app/drivers/crdlistener"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/app/drivers/eventconsumer"
	rest2 "openappsec.io/fog-msrv-waap-tuning-process/internal/app/drivers/http/rest"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/app/drivers/scheduler"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/app/tuningdomain/v1"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/app/tuningdomain/v2"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/pkg/db/intelligence"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/pkg/db/mongo"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/pkg/db/s3"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/pkg/db/sharedstorage"
	redis2 "openappsec.io/fog-msrv-waap-tuning-process/internal/pkg/lock/redis"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/pkg/mgmt/graphql"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/pkg/mgmt/rest"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/pkg/query"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/pkg/query/bqadapter"
	"openappsec.io/fog-msrv-waap-tuning-process/internal/pkg/query/pg"
	"openappsec.io/configuration"
	"openappsec.io/configuration/viper"
	"openappsec.io/health"
	"openappsec.io/jsonschema"
	"openappsec.io/kafka/consumermanager"
	"openappsec.io/mongodb"
	"openappsec.io/redis"
)

// Injectors from wire.go:

func InitializeApp(ctx context.Context) (*app.App, error) {
	adapter := viper.NewViper()
	service, err := configuration.NewConfigurationService(adapter)
	if err != nil {
		return nil, err
	}
	healthService := health.NewService()
	mongodbMongo := mongodb.NewClient()
	intelligenceAdapter, err := intelligence.NewAdapter(service)
	if err != nil {
		return nil, err
	}
	mongoAdapter, err := mongo.NewAdapter(service, mongodbMongo, intelligenceAdapter)
	if err != nil {
		return nil, err
	}
	restAdapter, err := rest.NewAdapter(service)
	if err != nil {
		return nil, err
	}
	v1Tuning, err := v1.NewTuningService(service, mongoAdapter, restAdapter)
	if err != nil {
		return nil, err
	}
	genBQQueries, err := bqadapter.NewQueriesGenerator(service)
	if err != nil {
		return nil, err
	}
	bqAdapter, err := bqadapter.NewBQAdapter(service)
	if err != nil {
		return nil, err
	}
	queryAdapter, err := query.NewAdapter(ctx, service, genBQQueries, bqAdapter)
	if err != nil {
		return nil, err
	}
	graphqlAdapter, err := graphql.NewAdapter(service)
	if err != nil {
		return nil, err
	}
	s3repositoryAdapter, err := s3repository.NewAdapter(service)
	if err != nil {
		return nil, err
	}
	redisAdapter := redis.NewClient()
	adapter2, err := redis2.NewAdapter(ctx, redisAdapter, service)
	if err != nil {
		return nil, err
	}
	tuningTuning, err := tuning.NewTuningService(service, queryAdapter, mongoAdapter, graphqlAdapter, s3repositoryAdapter, s3repositoryAdapter, adapter2, intelligenceAdapter)
	if err != nil {
		return nil, err
	}
	jsonschemaService := jsonschema.NewJSONSchemaService()
	adapter3, err := rest2.NewAdapter(service, healthService, v1Tuning, tuningTuning, queryAdapter, jsonschemaService)
	if err != nil {
		return nil, err
	}
	consumerManager := consumermanager.NewConsumerManager()
	eventconsumerAdapter, err := eventconsumer.NewAdapter(consumerManager, tuningTuning, service)
	if err != nil {
		return nil, err
	}
	appApp := app.NewApp(service, healthService, adapter3, eventconsumerAdapter, adapter2, mongoAdapter, intelligenceAdapter)
	return appApp, nil
}

func InitializeAppStandAlone(ctx context.Context) (*app.StandAlone, error) {
	adapter := viper.NewViper()
	service, err := configuration.NewConfigurationService(adapter)
	if err != nil {
		return nil, err
	}
	healthService := health.NewService()
	queriesGen, err := pg.NewQueriesGen(service)
	if err != nil {
		return nil, err
	}
	driver := pg.NewPQDriver()
	queryAdapter, err := query.NewAdapter(ctx, service, queriesGen, driver)
	if err != nil {
		return nil, err
	}
	sharedstorageAdapter, err := sharedstorage.NewAdapter(service)
	if err != nil {
		return nil, err
	}
	readerClient, err := crdlistener.NewReader(service)
	if err != nil {
		return nil, err
	}
	s3repositoryAdapter, err := s3repository.NewAdapter(service)
	if err != nil {
		return nil, err
	}
	standAlone := tuning.NewStandAlone(service, queryAdapter, sharedstorageAdapter, readerClient, s3repositoryAdapter, readerClient)
	adapterStandAlone, err := rest2.NewAdapterStandAlone(service, healthService, standAlone)
	if err != nil {
		return nil, err
	}
	crdlistenerAdapter, err := crdlistener.NewAdapter(standAlone, readerClient, service)
	if err != nil {
		return nil, err
	}
	schedulerAdapter, err := scheduler.NewAdapter(service, standAlone)
	if err != nil {
		return nil, err
	}
	appStandAlone := app.NewAppStandAlone(service, healthService, adapterStandAlone, crdlistenerAdapter, schedulerAdapter)
	return appStandAlone, nil
}