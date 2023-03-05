package mongodb

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"openappsec.io/errors"
	"openappsec.io/log"
	"openappsec.io/tracer"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
)

// IndexType indicates the type of index we want. For example ascending or descending
type IndexType int

// Index represents an index to be created in the given collection
type Index struct {
	Key       string
	IndexType IndexType
}

// index options consts
const (
	Ascending  IndexType = 1
	Descending IndexType = -1
)

// mongodb settings
const (
	MongoOpName = "golang-mongo"

	defaultTransactionAttempts       = 1
	defaultTransactionCommitAttempts = 3
)

// MongoConfig is a struct that holds the needed parameters for connection with mongo
type MongoConfig struct {
	URI        string
	Host       string
	Port       string
	Username   string
	Password   string
	Database   string
	Collection string
}

// Collation contains the options to define mongodb how to compare strings.
// Reference - https://docs.mongodb.com/upcoming/reference/collation/
type Collation struct {
	Locale          string
	CaseLevel       bool
	CaseFirst       string
	Strength        int
	NumericOrdering bool
	Alternate       string
	MaxVariable     string
	Normalization   bool
	Backwards       bool
}

// QueryOptions contains options for the FindByQuery operation
type QueryOptions struct {
	// Limit is how many items to return at the most
	Limit *int64
	Skip  *int64
	// Projection is the specific fields to return from DB
	Projection map[string]int
	// Hint is the index to use for the aggregation
	Hint interface{}
	// Collation defines how to compare strings in mongodb
	Collation *Collation
	// IsTextQuery is a boolean to mark if the query should be directed to Lucene or Mongo. Used only in case of an aggregation pipeline
	IsTextQuery bool
	// Search is the $search stage filter that's used if IsTextQuery is true
	Search map[string]interface{}
}

type metadata struct {
	Total int
}

// Facets is a struct with the facets reported by mongo
type Facets struct {
	Count map[string]interface{}  `json:"count" bson:"count"`
	Facet map[string]FacetsResult `json:"facet" bson:"facet"`
}

// WriteModel represent the mongo driver WriteModel
type WriteModel mongo.WriteModel

// BulkWriteResult represent the mongo driver BulkWriteResult
type BulkWriteResult mongo.BulkWriteResult

// String implements the Stringer interface. It instructs how to print the QueryOptions struct while using %+v, %v or %s
func (q QueryOptions) String() string {
	if q.Limit != nil && q.Skip != nil {
		return fmt.Sprintf("{Limit: %d Skip: %d Projection %+v Hint %+v Collation %+v}", *q.Limit, *q.Skip, q.Projection, q.Hint, q.Collation)
	}
	if q.Limit != nil {
		return fmt.Sprintf("{Limit: %d Skip: <nil> Projection %+v Hint %+v Collation %+v}", *q.Limit, q.Projection, q.Hint, q.Collation)
	}

	if q.Skip != nil {
		return fmt.Sprintf("{Limit: <nil> Skip: %d Projection %+v Hint %+v Collation %+v}", *q.Skip, q.Projection, q.Hint, q.Collation)
	}

	return fmt.Sprintf("{Limit: <nil> Skip: <nil> Projection %+v Hint %+v Collation %+v}", q.Projection, q.Hint, q.Collation)
}

// TransactionOptions contains options for the transaction operation
// Supported options are:
// Attempts - how many transactions to perform until success (default is 1)
// CommitAttempts - how many commit attempts to perform (for each transaction) until success (default is 3)
type TransactionOptions struct {
	Attempts       *int
	CommitAttempts *int
}

// String implements the Stringer interface. It instructs how to print the TransactionOptions struct while using %+v, %v or %s
func (t TransactionOptions) String() string {
	if t.Attempts != nil && t.CommitAttempts != nil {
		return fmt.Sprintf("{Attempts: %d CommitAttempts: %d}", *t.Attempts, *t.CommitAttempts)
	}
	if t.Attempts != nil {
		return fmt.Sprintf("{Attempts: %d CommitAttempts: <nil>}", *t.Attempts)
	}

	if t.CommitAttempts != nil {
		return fmt.Sprintf("{Attempts: <nil> CommitAttempts: %d}", *t.CommitAttempts)
	}

	return fmt.Sprint("{Attempts: <nil> CommitAttempts: <nil>}")
}

// FindOneOptions contains options for the GetOneByID operation
// Supported options are:
// Projection - specific fields to return from DB
type FindOneOptions struct {
	Projection map[string]int
}

// InsertManyOptions contains options for the InsertMany operation
// Supported options are:
// Ordered - If true, no writes will be executed after one fails. The default value is true.
type InsertManyOptions struct {
	Ordered *bool
}

// IndexOptions contains options for the InsertMany operation
// Supported options are:
// Sparse - If true, the index will only reference documents that contain the fields specified in the index.
// The default is false.
type IndexOptions struct {
	Sparse *bool
}

// PaginationMetadata contains metadata for paginated queries, such as the total number of results available and facets
type PaginationMetadata struct {
	Total  int
	Facets map[string]FacetsResult
}

// Facet is a struct capturing how a facet is presented when returned from Atlas.
// The ID matches the field "_id" - it's an interface with the applicable value of the faceted field.
// Count is the total count of how many times the value of the faceted field appears in DB
type Facet struct {
	ID    interface{} `json:"_id" bson:"_id"`
	Count int         `json:"count" bson:"count"`
}

// FacetsResult is how facets are returned from Atlas and how they are presented within the $$SEARCH_META variable.
type FacetsResult struct {
	Buckets []Facet `json:"buckets" bson:"buckets"`
}

// Mongo client for mongodb which specifies which database and collection to use
type Mongo struct {
	client     *mongo.Client
	collection *mongo.Collection
}

// UpdateResult contains a result values for update request
type UpdateResult struct {
	MatchedCount  int64       // The number of documents matched by the filter.
	ModifiedCount int64       // The number of documents modified by the operation.
	UpsertedCount int64       // The number of documents upserted by the operation.
	UpsertedID    interface{} // The _id field of the upserted document, or nil if no upsert was done.
}

// UpdateOperators contains update operator expressions
type UpdateOperators struct {
	Set         interface{} `bson:"$set,omitempty"`
	Unset       interface{} `bson:"$unset,omitempty"`
	SetOnInsert interface{} `bson:"$setOnInsert,omitempty"`
	Push        interface{} `bson:"$push,omitempty"`
	Pull        interface{} `bson:"$pull,omitempty"`
	AddToSet    interface{} `bson:"$addToSet,omitempty"`
	CurrentDate interface{} `bson:"$currentDate,omitempty"`
	Increment   interface{} `bson:"$inc,omitempty"`
}

// FindOneAndUpdateOptions contains options for FindOneAndUpdate operation
// Hint - the index to use for the operation. This should either be the index name as a string or the index specification as a document.
// Projection - specific fields to return from DB
type FindOneAndUpdateOptions struct {
	Projection map[string]int
	Hint       interface{}
}

// NewClient returns a mongodb adapter
func NewClient() *Mongo {
	return &Mongo{}
}

func connect(ctx context.Context, needCollection bool, mongodbConfiguration MongoConfig) (*mongo.Client, *mongo.Database, *mongo.Collection, error) {
	span := tracer.GlobalTracer().StartSpan(MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "connect")

	var serverURI string
	if uri := mongodbConfiguration.URI; uri != "" {
		serverURI = uri
	} else {
		var host string
		if host = mongodbConfiguration.Host; host == "" {
			ext.Error.Set(span, true)
			return nil, nil, nil, errors.Errorf("Missing host in mongodb configuration").SetClass(errors.ClassBadInput)
		}

		var port string
		if port = mongodbConfiguration.Port; port == "" {
			ext.Error.Set(span, true)
			return nil, nil, nil, errors.Errorf("Missing port in mongodb configuration").SetClass(errors.ClassBadInput)
		}

		username := mongodbConfiguration.Username
		password := mongodbConfiguration.Password

		if username == "" {
			serverURI = fmt.Sprintf("mongodb://%s:%s",
				host,
				port,
			)
		} else {
			serverURI = fmt.Sprintf("mongodb://%s:%s@%s:%s",
				username,
				password,
				host,
				port,
			)
		}
	}

	var database string
	if database = mongodbConfiguration.Database; database == "" {
		ext.Error.Set(span, true)
		return nil, nil, nil, errors.Errorf("Missing database in mongodb configuration").SetClass(errors.ClassBadInput)
	}

	var collection string
	if collection = mongodbConfiguration.Collection; needCollection && collection == "" {
		ext.Error.Set(span, true)
		return nil, nil, nil, errors.Errorf("Missing collection in mongodb configuration").SetClass(errors.ClassBadInput)
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(serverURI))
	if err != nil {
		ext.Error.Set(span, true)
		return nil, nil, nil, errors.Wrap(err, "Failed to connect to mongodb server").SetClass(errors.ClassInternal)
	}

	db := client.Database(database)

	if needCollection {
		if err := initCollection(ctx, client, database, collection); err != nil {
			ext.Error.Set(span, true)
			return nil, nil, nil, errors.Wrapf(err, "Failed to initialize collection (%s) on mongodb server", collection)
		}
	}

	return client, db, db.Collection(collection), nil
}
func collectionExists(ctx context.Context, client *mongo.Client, database string, collection string) (bool, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "collectionExists")

	cols, err := client.Database(database).ListCollectionNames(ctx, bson.D{{Key: "name", Value: collection}})
	if err != nil {
		ext.Error.Set(span, true)
		return false, errors.Wrapf(err, "Could not get list of collections").SetClass(errors.ClassInternal)
	}
	if len(cols) > 1 {
		ext.Error.Set(span, true)
		return false, errors.Errorf("Got too many collections (%+v)", cols).SetClass(errors.ClassInternal)
	}
	if len(cols) == 1 && cols[0] != collection {
		ext.Error.Set(span, true)
		return false, errors.Errorf("Got collection (%s) doesnt match want collection (%s)", cols[0], collection).SetClass(errors.ClassInternal)
	}

	return len(cols) == 1, nil
}

func initCollection(ctx context.Context, client *mongo.Client, database string, collection string) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "initCollection")

	exists, err := collectionExists(ctx, client, database, collection)
	if err != nil {
		ext.Error.Set(span, true)
		return errors.Wrapf(err, "Could not check if collection (%s) exists", collection).SetClass(errors.ClassInternal)
	}
	if exists {
		return nil
	}

	client.Database(database).RunCommand(ctx, map[string]interface{}{"create": collection})

	exists, err = collectionExists(ctx, client, database, collection)
	if err != nil {
		ext.Error.Set(span, true)
		return errors.Wrapf(err, "Could not check if collection (%s) exists", collection).SetClass(errors.ClassInternal)
	}
	if !exists {
		ext.Error.Set(span, true)
		return errors.Errorf("Collection (%s) was not created", collection).SetClass(errors.ClassInternal)
	}

	return nil
}

// Connect to mongodb
// These configuration fields are required in order to connect:
// host, port, username, password, db, collection
// Connect to mongodb
// These configuration fields are required in order to connect:
// host, port, username, password, db, collection
func (m *Mongo) Connect(ctx context.Context, mongodbConfiguration MongoConfig) error {
	client, _, collection, err := connect(ctx, true, mongodbConfiguration)
	if err != nil {
		return err
	}
	m.client = client
	m.collection = collection

	return nil
}

// HealthCheck pings mongodb server to check if it is accessible and alive
func (m *Mongo) HealthCheck(ctx context.Context) (string, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "HealthCheck")

	checkName := "Mongodb Ping Test"
	if err := m.client.Ping(ctx, readpref.Primary()); err != nil {
		ext.Error.Set(span, true)
		return checkName, errors.Wrap(err, "Cannot reach mongodb, failing health check").SetClass(errors.ClassInternal)
	}

	return checkName, nil
}

// CreateIndex create a mongo index in collection
// to create a compound index simply pass several fields
// Indexes are passed as part of a map. This  map contains, as keys, the fields we wish to index, and as values whether the indexes should be Descending or Ascending.
// to create a unique index set the 'unique' parameter to true
// This function supports an optional 'IndexOptions' argument to specify options for creating the index. Only one such struct may be passed.
func (m *Mongo) CreateIndex(ctx context.Context, index []Index, unique bool, opts ...*IndexOptions) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "CreateIndex")

	keys := make(bson.D, 0, len(index))
	for _, i := range index {
		keys = append(keys, bson.E{
			Key:   i.Key,
			Value: i.IndexType,
		})
	}

	indexOptions := &options.IndexOptions{}
	if len(opts) != 0 {
		if len(opts) > 1 {
			ext.Error.Set(span, true)
			return errors.Errorf("Too many 'IndexOptions' arguments passed to function").SetClass(errors.ClassBadInput)
		}
		indexOptions.Sparse = opts[0].Sparse
	}
	indexOptions.SetUnique(unique)

	in := mongo.IndexModel{
		Keys:    keys,
		Options: indexOptions,
	}

	if _, err := m.collection.Indexes().CreateOne(ctx, in); err != nil {
		ext.Error.Set(span, true)
		return errors.Wrap(err, "Failed to add index to collection").SetClass(errors.ClassInternal)
	}

	return nil
}

// DropIndex drop mongo index in collection
// to drop an index simply pass several fields:
// - index: contain the field of index and the index ordering type (ascending, descending)
func (m *Mongo) DropIndex(ctx context.Context, index Index) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "DropIndex")

	// to drop index the index field should concatenate with the index type (ascending, descending)
	indexToDrop := fmt.Sprintf("%s_%d", index.Key, index.IndexType)
	if _, err := m.collection.Indexes().DropOne(ctx, indexToDrop); err != nil {
		ext.Error.Set(span, true)
		return errors.Wrap(err, "Failed to drop index of collection").SetClass(errors.ClassInternal)
	}

	return nil
}

// CreateTTLIndex create a mongo TTL index in collection
func (m *Mongo) CreateTTLIndex(ctx context.Context, field string, indexType IndexType, ttl int32) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "CreateTTLIndex")

	index := mongo.IndexModel{
		Keys: map[string]interface{}{
			field: indexType,
		},
		Options: options.Index().SetExpireAfterSeconds(ttl),
	}

	if _, err := m.collection.Indexes().CreateOne(ctx, index); err != nil {
		ext.Error.Set(span, true)
		return errors.Wrap(err, "Failed to add TTL index to collection").SetClass(errors.ClassInternal)
	}

	return nil
}

// AddOne add document to mongodb, return the id of the document.
func (m *Mongo) AddOne(ctx context.Context, document interface{}) (interface{}, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "AddOne")

	res, err := m.collection.InsertOne(ctx, document)
	if err != nil {
		ext.Error.Set(span, true)
		return "", errors.Wrapf(err, "Failed to insert the following document to mongodb '%+v'", document).SetClass(errors.ClassInternal)
	}

	return res.InsertedID, nil
}

// AddMany add many documents to mongoDB, returns the ids of all added documents.
func (m *Mongo) AddMany(ctx context.Context, documents interface{}, opts ...*InsertManyOptions) ([]interface{}, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "AddMany")

	items := reflect.ValueOf(documents)
	if items.Kind() != reflect.Slice && items.Kind() != reflect.Array {
		ext.Error.Set(span, true)
		return nil, errors.New("documents should be 'Array' or 'Slice").SetClass(errors.ClassBadInput)
	}

	docs := make([]interface{}, items.Len())
	for i := 0; i < items.Len(); i++ {
		docs[i] = items.Index(i).Interface()
	}

	var res *mongo.InsertManyResult
	var err error
	if len(opts) != 0 {
		if len(opts) > 1 {
			ext.Error.Set(span, true)
			return nil, errors.Errorf("Too many 'InsertManyOptions' arguments passed to function").SetClass(errors.ClassBadInput)
		}
		res, err = m.collection.InsertMany(ctx, docs, &options.InsertManyOptions{
			Ordered: opts[0].Ordered,
		})
	} else {
		res, err = m.collection.InsertMany(ctx, docs)
	}

	if err != nil {
		ext.Error.Set(span, true)
		return res.InsertedIDs, errors.Wrapf(err, "Failed to insert the following documents to mongodb '%+v", docs).SetClass(errors.ClassInternal)
	}

	return res.InsertedIDs, nil
}

// GetOneByID get document by ID from mongodb, and put it in the paramter 'result'
// Note that 'result' should be a pointer to the desired type
func (m *Mongo) GetOneByID(ctx context.Context, id interface{}, result interface{}, opts ...*FindOneOptions) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "GetOneByID")
	var res *mongo.SingleResult

	if len(opts) != 0 {
		if len(opts) > 1 {
			return errors.Errorf("Too many 'FindOneOptions' arguments passed to function").SetClass(errors.ClassBadInput)
		}
		res = m.collection.FindOne(ctx, bson.M{"_id": id}, &options.FindOneOptions{
			Projection: opts[0].Projection,
		})
	} else {
		res = m.collection.FindOne(ctx, bson.M{"_id": id})
	}

	if res.Err() != nil {
		if res.Err() == mongo.ErrNoDocuments {
			ext.Error.Set(span, true)
			return errors.New("Document was not found").SetClass(errors.ClassNotFound)
		}
		ext.Error.Set(span, true)
		return errors.Wrapf(res.Err(), "Failed to find document with id (%s)", id).SetClass(errors.ClassInternal)
	}

	if err := res.Decode(result); err != nil {
		ext.Error.Set(span, true)
		return errors.Wrapf(err, "Failed to decode document to result type (%s)", reflect.TypeOf(result)).SetClass(errors.ClassBadInput)
	}

	return nil
}

// GetByQuery get documents by filter from mongodb, and put it in the parameter 'result'
// This function supports an optional 'QueryOptions' argument to specify options for the desired query. Only one such struct may be passed.
// Note that 'result' should be a pointer to a slice of the desired type
func (m *Mongo) GetByQuery(ctx context.Context, filter map[string]interface{}, results interface{}, opts ...*QueryOptions) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "GetByQuery")

	var res *mongo.Cursor
	var err error
	if len(opts) != 0 {
		if len(opts) > 1 {
			return errors.Errorf("Too many 'QueryOptions' arguments passed to function")
		}
		res, err = m.collection.Find(ctx, filter, &options.FindOptions{
			Limit:      opts[0].Limit,
			Skip:       opts[0].Skip,
			Projection: opts[0].Projection,
			Hint:       opts[0].Hint,
			Collation:  (*options.Collation)(opts[0].Collation),
		})
	} else {
		res, err = m.collection.Find(ctx, filter)
	}

	if err != nil {
		ext.Error.Set(span, true)
		return errors.Wrapf(err, "Failed to find documents with filter (%+v)", filter)
	}

	if err = res.All(ctx, results); err != nil {
		ext.Error.Set(span, true)
		return errors.Wrapf(err, "Failed to decode document to result type (%+v)", reflect.TypeOf(results))
	}

	return nil
}

// GetByQueryWithPagination - This function supports pagination via the limit, offset and sort arguments.
// limit - how many, at most, items to query for
// offset - how many, from the start, items to skip
// sort - the order in which to sort found results. Format is a map[string]int. The key being the field by which to sort and the value being 1 to sort upwards and -1 to sort downwards.  To sort upwards by field X specify: {"X": 1}
// opts - the query options, currently only Projection is supported for this operation.
// The functions return 'PaginationMetadata' in addition to placing the found items in the 'results' argument
func (m *Mongo) GetByQueryWithPagination(ctx context.Context, limit int, offset int, sort map[string]int, filter map[string]interface{}, results interface{}, opts ...*QueryOptions) (PaginationMetadata, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "GetByQueryWithPagination")

	var res *mongo.Cursor
	var err error

	matchStage := bson.D{{"$match", filter}}
	sortStage := bson.D{{"$sort", sort}}
	countStage := bson.D{{"$count", "total"}}
	limitStage := bson.D{{"$limit", limit}}
	skipStage := bson.D{{"$skip", offset}}

	metadataSubPipeline := bson.E{Key: "metadata", Value: bson.A{countStage}}
	dataSubPipeline := bson.E{Key: "data", Value: bson.A{skipStage, limitStage}}

	facet := bson.D{{"$facet", bson.D{metadataSubPipeline, dataSubPipeline}}}
	pipeline := mongo.Pipeline{matchStage, sortStage, facet}
	allowDiskUse := true
	args := options.AggregateOptions{AllowDiskUse: &allowDiskUse}
	if len(opts) != 0 {
		if len(opts) > 1 {
			ext.Error.Set(span, true)
			return PaginationMetadata{}, errors.Errorf("Too many 'QueryOptions' arguments passed to function")
		}

		var searchStage bson.D
		if opts[0].IsTextQuery {
			searchStage = bson.D{{"$search", opts[0].Search}}
			textSearchFacetPipeline := bson.E{Key: "facets", Value: bson.A{bson.D{{"$replaceWith", "$$SEARCH_META"}}, bson.D{{"$limit", 1}}}}
			facet = bson.D{{"$facet", bson.D{metadataSubPipeline, dataSubPipeline, textSearchFacetPipeline}}}
		}

		projectStage := bson.D{{"$project", opts[0].Projection}}
		pipeline = mongo.Pipeline{matchStage, sortStage, projectStage, facet}
		if searchStage != nil {
			pipeline = append([]bson.D{searchStage}, pipeline...)
		}

		args.Collation = (*options.Collation)(opts[0].Collation)
	}

	res, err = m.collection.Aggregate(ctx, pipeline, &args)
	if err != nil {
		ext.Error.Set(span, true)
		return PaginationMetadata{}, errors.Wrapf(err, "Failed to execute mongo aggregate (pipeline: %+v)", pipeline).SetClass(errors.ClassInternal)
	}

	type paginatedResult struct {
		Metadata []metadata
		Data     []bson.M
		Facets   []Facets
	}
	r := make([]paginatedResult, 1, 1)

	if err = res.All(ctx, &r); err != nil {
		ext.Error.Set(span, true)
		return PaginationMetadata{}, errors.Wrapf(err, "Failed to decode mongo result").SetClass(errors.ClassInternal)
	}

	if len(r) != 1 {
		// SANITY - this should never happen
		ext.Error.Set(span, true)
		return PaginationMetadata{}, errors.Errorf("Failed to get proper result from mongo. Got: %+v", r).SetClass(errors.ClassInternal)
	}

	metadataRes := PaginationMetadata{}
	// if didn't find any result in mongo, set total to 0
	if len(r[0].Metadata) != 1 {
		metadataRes.Total = 0
	} else {
		metadataRes.Total = r[0].Metadata[0].Total
	}

	// Update facets metadata if applicable
	if len(r[0].Facets) > 0 {
		metadataRes.Facets = r[0].Facets[0].Facet
	}

	// TODO - find a better way than marhsaling and unmarhsaling again
	jsn, err := json.Marshal(r[0].Data)
	if err != nil {
		return PaginationMetadata{}, errors.Wrap(err, "Failed to marshal resulting data from mongo").SetClass(errors.ClassInternal)
	}

	if err := json.Unmarshal(jsn, results); err != nil {
		return PaginationMetadata{}, errors.Wrap(err, "Failed to unmarshal results into user struct").SetClass(errors.ClassBadInput)
	}

	return metadataRes, nil
}

// QueryForFacetsWithTotalCount queries mongo and returns matching facets
func (m *Mongo) QueryForFacetsWithTotalCount(ctx context.Context, filter map[string]interface{}) (PaginationMetadata, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "QueryForFacetsWithTotalCount")

	var res *mongo.Cursor
	var err error

	countType := "total"

	// Add to the filter a "count" field to mark we are interested in total and not lowerBound (which is the default)
	filter["count"] = map[string]interface{}{"type": countType}
	searchStage := bson.D{{"$searchMeta", filter}}

	limitFacetPipeline := bson.E{Key: "facets", Value: bson.A{bson.D{{"$limit", 1}}}}
	facet := bson.D{{"$facet", bson.D{limitFacetPipeline}}}

	pipeline := mongo.Pipeline{searchStage, facet}
	allowDiskUse := true
	args := options.AggregateOptions{AllowDiskUse: &allowDiskUse}
	res, err = m.collection.Aggregate(ctx, pipeline, &args)
	if err != nil {
		ext.Error.Set(span, true)
		return PaginationMetadata{}, errors.Wrapf(err, "Failed to execute mongo aggregate (pipeline: %+v)", pipeline).SetClass(errors.ClassInternal)
	}

	type facetsResult struct {
		Facets []Facets
	}

	r := make([]facetsResult, 1, 1)
	if err = res.All(ctx, &r); err != nil {
		ext.Error.Set(span, true)
		return PaginationMetadata{}, errors.Wrapf(err, "Failed to decode mongo result").SetClass(errors.ClassInternal)
	}

	if len(r) != 1 || len(r[0].Facets) != 1 {
		// SANITY - this should never happen
		ext.Error.Set(span, true)
		return PaginationMetadata{}, errors.Errorf("Failed to get proper result from mongo. Got: %+v", r).SetClass(errors.ClassInternal)
	}

	metadataRes := PaginationMetadata{}
	total, ok := r[0].Facets[0].Count[countType].(int64)
	if !ok {
		return PaginationMetadata{}, errors.Errorf("Failed to assert %v field in facets result to int64 (type is %v). Result from mongo=%+v.", countType, reflect.TypeOf(r[0].Facets[0].Count[countType]), r).SetClass(errors.ClassInternal)
	}

	metadataRes.Total = int(total)
	metadataRes.Facets = r[0].Facets[0].Facet
	return metadataRes, nil
}

// GetAllDistinctValues finds a list of distinct values for a specified field across a single collection and returns it
func (m *Mongo) GetAllDistinctValues(ctx context.Context, fieldName string, filter map[string]interface{}) ([]interface{}, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "GetAllDistinctValues")

	res, err := m.collection.Distinct(ctx, fieldName, filter)
	if err != nil {
		ext.Error.Set(span, true)
		return nil, errors.Wrapf(err, "Failed to get all distinct values for key (%s) with filter (%+v)", fieldName, filter).SetClass(errors.ClassInternal)
	}

	return res, nil
}

// DeleteOneByID delete document by ID from mongoDB
func (m *Mongo) DeleteOneByID(ctx context.Context, id interface{}) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "DeleteOneByID")

	if _, err := m.collection.DeleteOne(ctx, bson.M{"_id": id}); err != nil {
		ext.Error.Set(span, true)
		return errors.Wrapf(err, "Failed to delete document with id (%s)", id).SetClass(errors.ClassInternal)
	}

	return nil
}

// DeleteByQuery delete document by filter from mongoDB, returns the number of deleted documents
func (m *Mongo) DeleteByQuery(ctx context.Context, filter map[string]interface{}) (int64, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "DeleteByQuery")

	res, err := m.collection.DeleteMany(ctx, filter)
	if err != nil {
		ext.Error.Set(span, true)
		return 0, errors.Wrapf(err, "Failed to delete documents with filter (%+v)", filter).SetClass(errors.ClassInternal)
	}

	return res.DeletedCount, nil
}

// TearDown disconnect from mongodb client
func (m *Mongo) TearDown(ctx context.Context) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "TearDown")

	log.Info("Tearing down mongodb adapter...")
	if err := m.client.Disconnect(ctx); err != nil {
		ext.Error.Set(span, true)
		return errors.Wrap(err, "Failed to close mongodb connections").SetClass(errors.ClassInternal)
	}

	return nil
}

// Transaction accepts a function to perform within a mongo transaction, this function should contain db operations
// all mongo related operations inside 'do' MUST use the the receiver of 'Transaction'
// This function assumes that the collection already exists, otherwise it will fail
func (m *Mongo) Transaction(ctx context.Context, do func(ctx context.Context) error, opts ...*TransactionOptions) error {
	span, _ := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "Transaction")

	attempts, commitAttempts, err := m.parseTransactionOptions(opts)
	if err != nil {
		return errors.Wrap(err, "Failed to parse transaction options")
	}

	var transactionErr error
	for i := 0; i < attempts; i++ {
		if transactionErr = m.client.UseSession(ctx, func(sctx mongo.SessionContext) error {

			err := sctx.StartTransaction(options.Transaction().
				SetReadConcern(readconcern.Snapshot()).
				SetWriteConcern(writeconcern.New(writeconcern.WMajority())),
			)
			if err != nil {
				ext.Error.Set(span, true)
				return errors.Wrap(err, "Failed to start mongo transaction")
			}
			if err := do(sctx); err != nil {
				ext.Error.Set(span, true)
				return errors.Wrap(err, "Error during transaction operation, aborting")
			}

			for i := 0; i < commitAttempts; i++ {
				err = sctx.CommitTransaction(sctx)
				switch e := err.(type) {
				case nil:
					return nil
				case mongo.CommandError:
					if e.HasErrorLabel("UnknownTransactionCommitResult") {
						log.Warnf("UnknownTransactionCommitResult, retrying commit operation. Error: %s", err)
						ext.Error.Set(span, true)
						continue
					}
					ext.Error.Set(span, true)
					return errors.Wrap(e, "Error during transaction commit")
				default:
					ext.Error.Set(span, true)
					return errors.Wrap(e, "Error during transaction commit")
				}
			}
			ext.Error.Set(span, true)
			return errors.Wrap(err, "All transaction commit attempts failed").SetClass(errors.ClassInternal)
		}); transactionErr != nil {
			log.Warnf("Transaction failed, retrying transaction. Error: %s", transactionErr)
			ext.Error.Set(span, true)
			continue
		}
		return nil
	}

	ext.Error.Set(span, true)
	return errors.Wrap(transactionErr, "All Transaction attempts failed").SetClass(errors.ClassInternal)
}

func (m *Mongo) parseTransactionOptions(opts []*TransactionOptions) (int, int, error) {
	attempts := defaultTransactionAttempts
	commitAttempts := defaultTransactionCommitAttempts

	if len(opts) > 1 {
		return 0, 0, errors.Errorf("TransactionOptions shouldn't contain more than one element")
	}
	if len(opts) < 1 {
		return attempts, commitAttempts, nil
	}

	opt := opts[0]

	if opt.Attempts != nil {
		if *opt.Attempts < 1 {
			return 0, 0, errors.Errorf("Bad option value for Attempts (%v), should be grater than 0", *opt.Attempts)
		}
		attempts = *opt.Attempts
	}

	if opt.CommitAttempts != nil {
		if *opt.CommitAttempts < 1 {
			return 0, 0, errors.Errorf("Bad option value for CommitAttempts (%v), should be grater than 0", *opt.CommitAttempts)
		}
		commitAttempts = *opt.CommitAttempts
	}

	return attempts, commitAttempts, nil
}

// FindOneAndReplace replaces one document in mongoDB and return the old document if exists.
// When 'upsert' argument is true, creates a new document if no document matches the query and ignores notFound error.
// If 'upsert' argument is false and no document matches the query, return notFound error.
// The function return a boolean value, true if there was an old document to replace and false otherwise.
func (m *Mongo) FindOneAndReplace(ctx context.Context, filter map[string]interface{}, item interface{}, result interface{}, upsert bool) (bool, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "FindOneAndReplace")

	findOneAndReplaceOptions := &options.FindOneAndReplaceOptions{
		Upsert: &upsert,
	}

	res := m.collection.FindOneAndReplace(ctx, filter, item, findOneAndReplaceOptions)
	if res.Err() != nil {
		// error in query
		if res.Err() != mongo.ErrNoDocuments {
			ext.Error.Set(span, true)
			return false, errors.Wrapf(res.Err(), "Failed to find document").SetClass(errors.ClassInternal)
		}
		// document does not found and upsert not set
		if !upsert {
			ext.Error.Set(span, true)
			return false, errors.New("Document was not found").SetClass(errors.ClassNotFound)
		}
		// document not found and inserted
		return false, nil
	}

	if err := res.Decode(result); err != nil {
		ext.Error.Set(span, true)
		return true, errors.Wrapf(err, "Failed to decode document to result type (%s)", reflect.TypeOf(result)).SetClass(errors.ClassBadInput)
	}

	return true, nil
}

// FindOneAndUpdate updates one document in mongoDB and return the old/updated (depends on 'after' parameter) document if exists.
// If 'after' is true then stores in resultPointer the updated document, otherwise it stores the old document.
// When 'upsert' argument is true, creates a new document if no document matches the query and ignores notFound error.
// If 'upsert' argument is false and no document matches the query, return notFound error.
// The function return a boolean value, true if there was an old document to update and false otherwise.
// result should be a pointer to a struct/object which can store the document.
func (m *Mongo) FindOneAndUpdate(ctx context.Context, filter map[string]interface{}, result interface{}, update UpdateOperators,
	after bool, upsert bool, opts ...*FindOneAndUpdateOptions) (bool, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "FindOneAndUpdate")

	if (UpdateOperators{}) == update {
		return false, errors.Errorf("Failed to update one document, got an empty UpdateOperators struct").SetClass(errors.ClassBadInput)
	}

	afterOrBeforeOption := options.After
	if !after {
		afterOrBeforeOption = options.Before
	}

	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &afterOrBeforeOption,
		Upsert:         &upsert,
	}

	if len(opts) != 0 {
		if len(opts) > 1 {
			ext.Error.Set(span, true)
			return false, errors.Errorf("Too many 'FindOneAndUpdateOptions' arguments passed to function").SetClass(errors.ClassBadInput)
		}
		opt.Hint = opts[0].Hint
		opt.Projection = opts[0].Projection
	}

	res := m.collection.FindOneAndUpdate(ctx, filter, update, &opt)
	if res.Err() != nil {
		// error in query
		if res.Err() != mongo.ErrNoDocuments {
			ext.Error.Set(span, true)
			return false, errors.Wrapf(res.Err(), "Failed to find and update document").SetClass(errors.ClassInternal)
		}

		// document does not found and upsert not set
		if !upsert {
			ext.Error.Set(span, true)
			return false, errors.New("Document was not found, and upsert=false").SetClass(errors.ClassNotFound)
		}

		// inserted new document and after=false
		return false, nil
	}

	if err := res.Decode(result); err != nil {
		ext.Error.Set(span, true)
		return true, errors.Wrapf(err, "Failed to decode document to result type (%s)", reflect.TypeOf(result)).SetClass(errors.ClassBadInput)
	}

	return true, nil

}

// FindOneAndDelete deletes one document in mongoDB and return the deleted document if exists.
// The function return a boolean value, true if there was an old document to delete and false otherwise.
// Returns an error in case the document was not found
func (m *Mongo) FindOneAndDelete(ctx context.Context, filter map[string]interface{}, result interface{}) (bool, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "FindOneAndDelete")

	res := m.collection.FindOneAndDelete(ctx, filter, &options.FindOneAndDeleteOptions{})
	if res.Err() != nil {
		// error in query
		if res.Err() != mongo.ErrNoDocuments {
			ext.Error.Set(span, true)
			return false, errors.Wrapf(res.Err(), "Failed to find document").SetClass(errors.ClassInternal)
		}

		// document wasn't found
		ext.Error.Set(span, true)
		return false, errors.New("Document was not found").SetClass(errors.ClassNotFound)
	}

	if err := res.Decode(result); err != nil {
		ext.Error.Set(span, true)
		return true, errors.Wrapf(err, "Failed to decode document to result type (%s)", reflect.TypeOf(result)).SetClass(errors.ClassBadInput)
	}

	return true, nil
}

// ReplaceOne replaces one documents in mongoDB, if it exists it is overridden otherwise added
func (m *Mongo) ReplaceOne(ctx context.Context, filter map[string]interface{}, item interface{}) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "ReplaceOne")

	upsert := true
	res, err := m.collection.ReplaceOne(ctx, filter, item, &options.ReplaceOptions{
		Upsert: &upsert,
	})
	if err != nil {
		ext.Error.Set(span, true)
		return errors.Wrapf(err, "Failed to insert the following document to mongodb '%+v", item).SetClass(errors.ClassInternal)
	}
	log.WithContext(ctx).Debugf("Mongo ReplaceOne operation result: %+v", res)

	return nil
}

// UpdateOne updates the first document that match the filter in mongodb.
// When 'upsert' argument is true, creates a new document if no document matches the query.
func (m *Mongo) UpdateOne(ctx context.Context, filter map[string]interface{}, update UpdateOperators, upsert bool) (UpdateResult, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "UpdateOne")

	if (UpdateOperators{}) == update {
		return UpdateResult{}, errors.Errorf("Failed to update one document, got an empty UpdateOperators struct").SetClass(errors.ClassBadInput)
	}

	updateOptions := &options.UpdateOptions{
		Upsert: &upsert,
	}

	res, err := m.collection.UpdateOne(ctx, filter, update, updateOptions)
	if err != nil {
		ext.Error.Set(span, true)
		return UpdateResult{}, errors.Wrapf(err, "Failed to update one document to (%+v) for filter (%+v) in mongodb", update, filter).SetClass(errors.ClassInternal)
	}

	return UpdateResult{
		ModifiedCount: res.ModifiedCount,
		MatchedCount:  res.MatchedCount,
		UpsertedCount: res.UpsertedCount,
		UpsertedID:    res.UpsertedID,
	}, nil
}

// UpdateMany updates all documents that match the filter in mongoDB.
// When 'upsert' argument is true, creates a new document if no document matches the query.
func (m *Mongo) UpdateMany(ctx context.Context, filter map[string]interface{}, update UpdateOperators, upsert bool) (UpdateResult, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "UpdateMany")

	if (UpdateOperators{}) == update {
		return UpdateResult{}, errors.Errorf("Failed to update many documents, got an empty UpdateOperators struct").SetClass(errors.ClassBadInput)
	}

	updateOptions := &options.UpdateOptions{
		Upsert: &upsert,
	}

	res, err := m.collection.UpdateMany(ctx, filter, update, updateOptions)
	if err != nil {
		ext.Error.Set(span, true)
		return UpdateResult{}, errors.Wrapf(err, "Failed to update many documents to (%+v) for filter (%+v) in mongodb", update, filter).SetClass(errors.ClassInternal)
	}

	return UpdateResult{
		ModifiedCount: res.ModifiedCount,
		MatchedCount:  res.MatchedCount,
		UpsertedCount: res.UpsertedCount,
		UpsertedID:    res.UpsertedID,
	}, nil
}

// GetClient returns the mongo client that works with the collection defined during executing of `Connect` function
func (m *Mongo) GetClient() *mongo.Collection {
	return m.collection
}

// Count counts the number of documents matching the filter.
// It returns an error in case operation failed
func (m *Mongo) Count(ctx context.Context, filter map[string]interface{}) (int64, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "Count")

	return m.collection.CountDocuments(ctx, filter)
}

// AggregateSumByField perform mongo db aggregation sum query according to the filter and query
func (m *Mongo) AggregateSumByField(ctx context.Context, filter, query map[string]interface{}) (int, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "Aggregate")

	// matchStage present the filter of the aggregation
	matchStage := bson.D{{"$match", filter}}
	// groupStage present the grouping to sum by a certain filed
	groupStage := bson.D{{"$group", bson.D{{"_id", nil}, {"sum", query}}}}

	showInfoCursor, err := m.collection.Aggregate(ctx, mongo.Pipeline{matchStage, groupStage})
	if err != nil {
		return 0, errors.Wrapf(err, "failed to perform aggregation query (%+v) and filter (%+v)", query, filter).SetClass(errors.ClassInternal)
	}

	// sumResult present the expected result struct
	type sumResult struct {
		ID  string `json:"_id" bson:"_id"`
		Sum int    `json:"sum" bson:"sum"`
	}
	results := make([]sumResult, 1, 1)

	if err = showInfoCursor.All(ctx, &results); err != nil {
		return 0, errors.Wrapf(err, "failed extract result from aggregation query (%+v) and filter (%+v)", query, filter).SetClass(errors.ClassInternal)
	}

	// if result is empty then result not found by filter and query
	if len(results) == 0 {
		return 0, errors.Errorf("document not found by query (%+v) and filter (%+v)", query, filter).SetClass(errors.ClassNotFound)
	}

	return results[0].Sum, nil
}

// BulkWrite perform bulk operation by the given write models in an ordered or unordered fashion
func (m *Mongo) BulkWrite(ctx context.Context, ordered bool, writeModels []WriteModel) (BulkWriteResult, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "BulkWrite")

	operations := make([]mongo.WriteModel, len(writeModels))
	for i := 0; i < len(writeModels); i++ {
		operations[i] = mongo.WriteModel(writeModels[i])
	}

	opts := options.BulkWrite().SetOrdered(ordered)
	results, err := m.collection.BulkWrite(ctx, operations, opts)
	if err != nil {
		return BulkWriteResult{}, errors.Wrap(err, "Failed to execute bulk write operation").SetClass(errors.ClassInternal)
	}

	if results == nil {
		return BulkWriteResult{}, errors.Errorf("Failed to execute bulk write operation, bulk write result is missing").SetClass(
			errors.ClassInternal)
	}

	return BulkWriteResult(*results), nil
}
