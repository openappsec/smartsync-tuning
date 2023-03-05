package mongodb

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
)

// CollectionlessMongo client for mongodb which specifies which database to use
type CollectionlessMongo struct {
	client   *mongo.Client
	dataBase *mongo.Database
}

// NewCollectionlessMongo returns a mongodb adapter with only a db
func NewCollectionlessMongo() *CollectionlessMongo {
	return &CollectionlessMongo{}
}

// CreateCollection creates a collection. error if failed to create or already exists
func (m *CollectionlessMongo) CreateCollection(ctx context.Context, collection string) error {
	return initCollection(ctx, m.client, m.dataBase.Name(), collection)
}

// Connect to mongodb
// These configuration fields are required in order to connect:
// host, port, username, password, db, collection
func (m *CollectionlessMongo) Connect(ctx context.Context, mongodbConfiguration MongoConfig) error {

	client, database, _, err := connect(ctx, false, mongodbConfiguration)
	if err != nil {
		return err
	}
	m.client = client
	m.dataBase = database

	return nil
}

// HealthCheck pings mongodb server to check if it is accessible and alive
func (m *CollectionlessMongo) HealthCheck(ctx context.Context) (string, error) {
	mongo := &Mongo{
		client: m.client,
	}
	return mongo.HealthCheck(ctx)
}

// DropIndex drop mongo index in collection
// to drop an index simply pass several fields:
// - collection: the collection name to drop index for
// - index: contain the field of index and the index ordering type (ascending, descending)
func (m *CollectionlessMongo) DropIndex(ctx context.Context, collection string, index Index) error {
	mongoClient := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongoClient.DropIndex(ctx, index)
}

// CreateTTLIndex create a mongo TTL index in collection
func (m *CollectionlessMongo) CreateTTLIndex(ctx context.Context, collection string, field string, indexType IndexType, ttl int32) error {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.CreateTTLIndex(ctx, field, indexType, ttl)
}

// CreateIndex create a mongo index in a given collection
// to create a compound index simply pass several fields
// Indexes are passed as part of a map. This  map contains, as keys, the fields we wish to index, and as values whether the indexes should be Descending or Ascending.
// to create a unique index set the 'unique' parameter to true
// This function supports an optional 'IndexOptions' argument to specify options for creating the index. Only one such struct may be passed.
func (m *CollectionlessMongo) CreateIndex(ctx context.Context, collection string, indexes []Index, unique bool, opts ...*IndexOptions) error {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.CreateIndex(ctx, indexes, unique, opts...)
}

// AddOne add document to mongodb, return the id of the document.
func (m *CollectionlessMongo) AddOne(ctx context.Context, collection string, document interface{}) (interface{}, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.AddOne(ctx, document)
}

// AddMany add many documents to mongoDB, returns the ids of all added documents.
func (m *CollectionlessMongo) AddMany(ctx context.Context, collection string, documents interface{}, opts ...*InsertManyOptions) ([]interface{}, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	if len(opts) > 0 {
		return mongo.AddMany(ctx, documents, opts[0])
	}
	return mongo.AddMany(ctx, documents)
}

// GetOneByID get document by ID from mongodb, and put it in the paramter 'result'
// Note that 'result' should be a pointer to the desired type
func (m *CollectionlessMongo) GetOneByID(ctx context.Context, collection string, id interface{}, result interface{}, opts ...*FindOneOptions) error {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.GetOneByID(ctx, id, result, opts...)
}

// GetByQuery get documents by filter from mongodb, and put it in the parameter 'result'
// This function supports an optional 'QueryOptions' argument to specify options for the desired query. Only one such struct may be passed.
// Note that 'result' should be a pointer to a slice of the desired type
func (m *CollectionlessMongo) GetByQuery(ctx context.Context, collection string, filter map[string]interface{}, results interface{}, opts ...*QueryOptions) error {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.GetByQuery(ctx, filter, results, opts...)
}

// GetByQueryWithPagination - This function supports pagination via the limit, offset and sort arguments.
// limit - how many, at most, items to query for
// offset - how many, from the start, items to skip
// sort - the order in which to sort found results. Format is a map[string]int. The key being the field by which to sort and the value being 1 to sort upwards and -1 to sort downwards.  To sort upwards by field X specify: {"X": 1}
// opts - the query options, currently only Projection is supported for this operation.
// The functions returns 'PaginationMetadata' in addition to placing the found items in the 'results' argument
func (m *CollectionlessMongo) GetByQueryWithPagination(ctx context.Context, collection string, limit int, offset int, sort map[string]int, filter map[string]interface{}, results interface{}, opts ...*QueryOptions) (PaginationMetadata, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.GetByQueryWithPagination(ctx, limit, offset, sort, filter, results, opts...)
}

// QueryForFacetsWithTotalCount queries mongo and returns matching facets
func (m *CollectionlessMongo) QueryForFacetsWithTotalCount(ctx context.Context, collection string, filter map[string]interface{}) (PaginationMetadata, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}

	return mongo.QueryForFacetsWithTotalCount(ctx, filter)
}

// GetAllDistinctValues finds a list of distinct values for a specified field across a single collection and returns it
func (m *CollectionlessMongo) GetAllDistinctValues(ctx context.Context, collection string, fieldName string, filter map[string]interface{}) ([]interface{}, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.GetAllDistinctValues(ctx, fieldName, filter)
}

// DeleteOneByID delete document by ID from mongoDB
func (m *CollectionlessMongo) DeleteOneByID(ctx context.Context, collection string, id interface{}) error {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.DeleteOneByID(ctx, id)
}

// DeleteByQuery delete document by filter from mongoDB, returns the number of deleted documents
func (m *CollectionlessMongo) DeleteByQuery(ctx context.Context, collection string, filter map[string]interface{}) (int64, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.DeleteByQuery(ctx, filter)
}

// TearDown disconnect from mongodb client
func (m *CollectionlessMongo) TearDown(ctx context.Context) error {
	mongo := &Mongo{
		client: m.client,
	}
	return mongo.TearDown(ctx)
}

// Transaction accepts a function to perform within a mongo transaction, this function should contain db operations
// all mongo related operations inside 'do' MUST use the the receiver of 'Transaction'
func (m *CollectionlessMongo) Transaction(ctx context.Context, do func(ctx context.Context) error, opts ...*TransactionOptions) error {
	mongo := &Mongo{
		client: m.client,
	}
	if len(opts) > 0 {
		return mongo.Transaction(ctx, do, opts[0])
	}
	return mongo.Transaction(ctx, do)
}

// FindOneAndReplace replaces one document in mongoDB and return the old document if exists.
// When 'upsert' argument is true, creates a new document if no document matches the query and ignores notFound error.
// If 'upsert' argument is false and no document matches the query, return notFound error.
// The function return a boolean value, true if there was an old document to replace and false otherwise.
func (m *CollectionlessMongo) FindOneAndReplace(ctx context.Context, collection string, filter map[string]interface{}, item interface{}, result interface{}, upsert bool) (bool, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.FindOneAndReplace(ctx, filter, item, result, upsert)
}

// FindOneAndUpdate updates one document in mongoDB and return the old/updated (depends on after parameter) document if exists.
// If 'after' is true then stores in resultPointer the updated document, otherwise it stores the old document.
// When 'upsert' argument is true, creates a new document if no document matches the query and ignores notFound error.
// If 'upsert' argument is false and no document matches the query, return notFound error.
// The function return a boolean value, true if there was an old document to update and false otherwise.
// result should be a pointer to a struct/object which can store the document.
func (m *CollectionlessMongo) FindOneAndUpdate(ctx context.Context, collection string, filter map[string]interface{}, result interface{}, update UpdateOperators,
	after bool, upsert bool, opts ...*FindOneAndUpdateOptions) (bool, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	if len(opts) > 0 {
		return mongo.FindOneAndUpdate(ctx, filter, result, update, after, upsert, opts[0])
	}
	return mongo.FindOneAndUpdate(ctx, filter, result, update, after, upsert)
}

// FindOneAndDelete deletes one document in mongoDB and return the deleted document if exists.
// The function return a boolean value, true if there was an old document to delete and false otherwise.
func (m *CollectionlessMongo) FindOneAndDelete(ctx context.Context, collection string, filter map[string]interface{}, result interface{}) (bool, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.FindOneAndDelete(ctx, filter, result)
}

// ReplaceOne replaces one documents in mongoDB, if it exists it is overridden otherwise added
func (m *CollectionlessMongo) ReplaceOne(ctx context.Context, collection string, filter map[string]interface{}, item interface{}) error {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.ReplaceOne(ctx, filter, item)
}

// UpdateOne updates the first document that match the filter in mongodb.
// When 'upsert' argument is true, creates a new document if no document matches the query.
func (m *CollectionlessMongo) UpdateOne(ctx context.Context, collection string, filter map[string]interface{}, update UpdateOperators, upsert bool) (UpdateResult, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.UpdateOne(ctx, filter, update, upsert)
}

// UpdateMany updates all documents that match the filter in mongoDB.
// When 'upsert' argument is true, creates a new document if no document matches the query.
func (m *CollectionlessMongo) UpdateMany(ctx context.Context, collection string, filter map[string]interface{}, update UpdateOperators, upsert bool) (UpdateResult, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.UpdateMany(ctx, filter, update, upsert)
}

// GetClient gets collection and returns the mongo client that works with this collection
func (m *CollectionlessMongo) GetClient(collection string) *mongo.Collection {
	return m.dataBase.Collection(collection)
}

// Count counts the number of documents matching the filter.
// It returns an error in case operation failed
func (m *CollectionlessMongo) Count(ctx context.Context, collection string, filter map[string]interface{}) (int64, error) {
	mongo := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}
	return mongo.Count(ctx, filter)
}

// AggregateSumByField perform mongo db aggregation sum query according to the filter and query
func (m *CollectionlessMongo) AggregateSumByField(ctx context.Context, collection string, filter, query map[string]interface{}) (int, error) {
	mongoClient := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}

	return mongoClient.AggregateSumByField(ctx, filter, query)
}

// BulkWrite perform bulk operation by the given write models in an ordered or unordered fashion
func (m *CollectionlessMongo) BulkWrite(ctx context.Context, collection string, ordered bool, writeModels []WriteModel) (BulkWriteResult, error) {
	mongoClient := &Mongo{
		client:     m.client,
		collection: m.dataBase.Collection(collection),
	}

	return mongoClient.BulkWrite(ctx, ordered, writeModels)
}
