# MongoDB

A package aimed to give convenient access to the official mongodb golang driver

## Capabilities:

### NewClient:

Creates a new, uninitialized client. To render the client usable call the `Connect` method. 

### Connect:

This function accepts a context and a map with configuration for the mongo connection.

The fields that can be passed in the configuration can be seen in the table below.<br>
A series of convenience consts are exposed by this package to be used when setting the fields and their values into a map.

| Name             | Field Name   | Const                | Description                                                                                                                                                             |
|------------------|--------------|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Mongodb hostname | `host`       | `MongoHostKey`       | the hostname of the mongo server to which you'd like to connect.                                                                                            |
| Port             | `port`       | `MongoPortKey`       | the port for the mongo connection.                                                                                                                                      |
| Username         | `username`   | `MongoUsernameKey`   | when auth is enabled, this field specifies what user to connect with.                                                                                                    |
| Password         | `password`   | `MongoPasswordKey`   | when auth is enabled, this field specifies the password with which to connect.                                                                                           |
| Database         | `database`   | `MongoDatabseKey`    | the database to which the connection should be opened.                                                                                                                   |
| Collection       | `collection` | `MongoCollectionKey` | the collection within the given database to connect to. If the collection does not exist it will be created.                                                                                                                   |
| URI              | `uri`        | `MongoURIKey`        | an alternative to specifying a hostname, port, username, and password.<br>See detials on the format [here](https://docs.mongodb.com/manual/reference/connection-string/). |

### HealthCheck:

Exposes a healthcheck function to be used in various readiness checks. This healthcheck executes a MonogDB PING operation.

### CreateIndex:

Can be used to create an index in the configured collection. <br>
Accepts a slice of index fields, where each field contains the key and the sorting direction for said key, and a boolean `unique` flag. <br>
If `unique` is set to `true` then the created index is a unique index. 
The function supports `IndexOptions`, an optional argument. Currently supported options:

| Name             | Description             |                                                                                                                                 
|------------------|--------------------------|
| Sparse | If true, the index will only reference documents that contain the fields specified in the index. The default is false.   |  

Example:

```go
    indexToCreate := []Index{
    		{indexType: Ascending, Key: "field1"},
    		{indexType: Descending, Key: "field2"},
    	}
	if err := m.CreateIndex(ctx, indexToCreate, false); err != nil {
		...
	}
```

### CreateTTLIndex:

Can be used to create a TTL index in the configured collection. <br>
Accepts a field to index, its sorting direction, and the TTL, in seconds, after which to expire the indexed document <br>
The indexed field needs to be a datetime variable. The document will expire at the date in said field plus the given TTL.

### DropIndex:

Can be used to drop index in the configured collection. <br>
function accept the following <br>

| Name             | Description                                                               |                                                                                                                                 
|------------------|---------------------------------------------------------------------------|
| collection | the name of the collection.                                                     |  
| index      | contain the field of index and the index ordering type (ascending, descending). |

### AddOne:

Accepts an `interface{}` document and adds it to the configured collection. Returns the `_id` of the inserted document and a nil error upon success an actual error upon failure. <br>
**Please notice** that when inserting a struct variable, the field names are set by default as the struct field names, **in a lower-case letters**. <br>
For example, if a field name in a struct is `GdwUuid` then the field name in the mongo document will be `gwuuid`. <br>
To set custom field names use `bson` tags (possibly followed by a comma-separated list of options), for example:
```go
type Document struct {
	ProfileID     string                 `bson:"profileId"`
	TenantID      string                 `bson:"tenantId"`
	Version       int                    `bson:"policyVersion"`
	Data          map[string]interface{} `bson:"policyData,omitempty"`  // omitempty: the field will not be marshalled if it is set to the zero value
	CreatedAt     time.Time              `bson:"createdAt"`
	ModifiedAt    time.Time              `bson:"modifiedAt"`
}
```
For more options and details, see the official mongo-go-driver documentation [here](https://pkg.go.dev/go.mongodb.org/mongo-driver/bson#hdr-Structs).

### AddMany:

Behaves similar to the `AddOne` method. Accepting a list of documents, inserting them, and returning a list of inserted IDs upon success. <br> 
The function supports `InsertManyOptions`, an optional argument. Currently supported options:

| Name             | Description             |                                                                                                                                 
|------------------|--------------------------|
| Ordered | If true, no writes will be executed after one fails. The default value is true.   |   

### GetByID:

Accepts an ID (`interface{}`), a pointer to a struct into which the query result should be decoded, and options. <br>
If the ID is not found a `ClassNotFound` error is returned. <br>
Upon success the result is placed into the given struct pointer and a nil error is returned. 
The function supports `FindOneOptions`, an optional argument. Currently supported options:

| Name             | Description             |                                                                                                                                 
|------------------|--------------------------|
| Projection | Specific field to return from query   |     

For example, a filter looking for single document by id with the value `123`, return specific fields ('name') from query, would look like this:

```go
filter := interface{}{"123"}
projection := make(map[string]int)
projection["name"] = 1

var ms []myStruct
if err := as.repo.GetOneByID(ctx, filter, &ms, &FindOneOptions{
                  		Projection: projection,
                  	}); err != nil {
    return models.Account{}, errors.Wrap(err, "Failed to get ...").SetClass(errors.ClassInternal)

}
```

### GetByQuery:

Behaves like `GetByID` but instead of accepting an ID, it accepts a mongo filter. <br>
Note that the result of the query will be a slice of documents, therefore the function should accept a pointer to a slice of struct as opposed to a single struct like in `GetByID`.<br>
The function supports `QueryOptions`, an optional argument. Currently supported options:

| Name             | Description             |                                                                                                                                 
|------------------|--------------------------|
| Limit | The maximum number of documents to find   | 
| Skip | The number of documents to skip before adding documents to the result   | 
| Projection | Specific field to return from query   |  
| Hint | The index to use for the aggregation   | 
| Collation | Defines how to compare strings in mongodb |

For example, a filter looking for all documents with the field `tenantID` with the value `123`, looking for at most 5 items, return specific fields ('name') from query, would look like this:

```go
filter := map[string]interface{}{
    "tenantID": "123",
}
limit := int64(5)
projection := make(map[string]int)
projection["name"] = 1
var ms []myStruct
if err := as.repo.GetByQuery(ctx, filter, &ms, &QueryOptions{
                  		Limit:  &limit,
                  		Projection: projection,
                  	}); err != nil {
    return models.Account{}, errors.Wrap(err, "Failed to get ...").SetClass(errors.ClassInternal)

}
```

### GetByQueryWithPagination

Similar to GetByQuery, with the addition of pagination. The function accepts:
* `filter` indicating which documents to find
* `limit` indicating how many should be returned
* `offset` indicating how many documents from the start should not be returned
* `sort` indicating if the found items should be iterated in ascending or descending order. For example, to sort upwards by field X specify: {"X": 1}. Use -1 for downwards sort.
* `opts` indicating the options for the query

The function loads the desired results into the `results` argument. Note that this argument must be a pointer to a slice of the desired type.
In addition, this function returns `PaginationMetadata` containing meta information about the query result, such as the total number of documents matching the provided filter in the DB.

### QueryForFacetsWithTotalCount

Applicable only when using Atlas with version 5.2 and above (Mongo integrated with Lucene). The query is directed to Lucene, and returns only the metadata of the query which contains the facets.

### GetAllDistinctValues:

Accepts a field name and a filter.<br>
Returns all the distinct values for the given field, from within all documents matching the given filter. 

For example, getting all tenantIDs in a collection, where tenantID is a field within the collection documents:

```go
GetAllDistinctValues(ctx, "tenantID", map[string]interface{}{}) // empty map -> empty filter -> search all documents 
```

### DeleteOneByID:

Accepts an ID for a document and deletes it from the configured collection. If a document with the given ID does not exist, no error is returned. <br>
Returns an error on failure.

### DeleteByQuery:

Accepts a filter (similar to `GetByQuery`) and deletes all documents matching the filter in the configured collection. <br>
Returns the number of deleted documents and an error if applicable. 

### ReplaceOne:

Accepts a filter and an item. 
Replaces the first document matching the given filter with the given item, in the configured collection. If no such document is found then the given item is simply added to the collection. 

### FindOneAndReplace:

Accepts a filter, document, pointer to a struct into which the query result should be decoded and an upsert flag. 
Find the first document matching the given filter with the given document, in the configured collection.
If upsert flag is on and no such document is found then the given document is simply added to the collection.
Returns bool which is true if there was a matching document or false otherwise and an error on failure.

### FindOneAndDelete:

Accepts a filter and a pointer to a struct into which the query result should be decoded.
Find the first document matching the given filter, deletes the document and updates the provided pointer.
Returns bool which is true if there was a matching document or false otherwise and an error on failure.
Returns an error in case the document was not found.

### UpdateOne:

Accepts a filter, updateOperations and upsert flag. 
Update the first document matching the given filter with the given document, in the configured collection.
If upsert flag is on and no such document is found then the given document is simply added to the collection.

For example, creating a person document using the `upsert=true` option and then updating the persons age. 
```go
update := UpdateOperators{
    SetOnInsert: Person{Name: "Tamir"},
    Set:         Person{Age: 27},
}

nameFilter := map[string]interface{}{
    "name": "Tamir",
}
upsert := true

updateRes, err := m.UpdateOne(ctx, nameFilter, update, upsert)
if err != nil {
    ...
}
```
UpdateOperators options descriptions:

| Name             | Description             |                                                                                                                                 
|------------------|--------------------------|
| Increment | increment a certain field by the increment value in such form: { <field1>: <amount1>, <field2>: <amount2>, ... } |   

### FindOneAndUpdate
- Accepts a context object, filter, pointer to a struct into which the query result should be decoded, an update (UpdateOperators struct),
an 'upsert' flag, an 'after' flag (if true the pointed struct will hold the updated document, otherwise, the old document version) and
a pointer to a FindOneAndUpdateOptions struct.
- If upsert flag is true and no such document is found, then the given "updateDoc" is simply added as a document to the collection.
- Returns bool which is true if there was a matching document or false otherwise and an error on failure.
For example:
```go
package stam
import "time"

type Person struct {
    Name string
    Age int
    Birthday *time.Time 
}

filter := map[string]interface{}{
		"name": "Nadav",
}

upsert := true
after := true
var person Person
projection := map[string]int{}{
    "name": 1,
    "age": 1,
    "bithday": 0,
}

updateDoc := map[string]interface{}{
    "age":  28,
}

update := UpdateOperators{
    Set: updateDoc,
}
opt := FindOneAndUpdateOptions{
    Projection: projection
}

isUpdated, err := as.repo.FindOneAndUpdate(ctx, filter, &person, update, after, upsert, &opt)
```

### UpdateMany:

Accepts a filter, document and upsert flag. 
Update all documents matching the given filter with the given updateOperations, in the configured collection.
If upsert flag is on and no such document is found then the given document is simply added to the collection. 

### Transaction:

> <b>NOTE</b>: All other operations in this package are <b>not</b> transactional. In order to make them transactional they should be wrapped with this function.

Accepts a function which will be run within a mongo transactional session. <br>
The function, in turn, accepts a context. All mongo operations within this function must use this context in order to be part of the mongo session.   
The function supports `TransactionOptions`, an optional argument. Currently supported options:

| Name             | Description             |                                                                                                                                 
|------------------|--------------------------|
| Attempts | How many transactions to perform until success (default is 1)   | 
| CommitAttempts | How many commit attempts to perform (for each transaction) until success (default is 3)   | 

For example, using AddMany within a transaction (if one addition fails, they all will), with 2 transaction attempts and 4 commit attpemts:

```go
p1 := Person{
    Name: "Tamir",
    Age:  27,
}

p2 := Person{
    Name: "Aviv",
    Age:  27,
}

documents := []Person{p1, p2}
var documentIDs []interface{}
attempts := 2
commitAttempts := 4
if err := m.Transaction(ctx, func(c context.Context) error {
    var e error
    documentIDs, e = m.AddMany(c, documents)
    if e != nil {
        return e
    }
    return nil
}, &TransactionOptions{
        Attempts: &attempts,
        CommitAttempts: &commitAttempts
}); err != nil {
    t.Fatalf("Failed to InsertMany in a transaction. Error: %s", err)
}
```
### Count:
Counts the number of documents matching the filter. It returns an error in case operation failed

### GetClient:
Returns the mongo client that works directly with the collection defined during executing of `Connect` function.

> <b>NOTE</b>: If possible, it's preferable to use one of functions from the library. <br> When using mongo operations by accessing directly the mongo client - it's the responsibility of the developer to start/close the tracing span, if needed.

For example, using mongo's BulkWrite() by accessing directly the mongo client:
```go
// To make the mongo client operations being testable by creating required mocks
type MongoClient interface {
	BulkWrite(ctx context.Context, models []mongodriver.WriteModel, opts ...*options.BulkWriteOptions) (*mongodriver.BulkWriteResult, error)
}

// Adapter is the component that communicates with the db library
type Adapter struct {
	mongo       Mongo
	mongoClient MongoClient
}

// NewAdapter creates an adapter to communicate with mongo
func NewAdapter(ctx context.Context, conf Configuration, mongo Mongo) (*Adapter, error) {
        ...
	repoConf := mongodb.MongoConfig{
		URI:        uri,
		Database:   database,
		Collection: collection,
	}

	if err := mongo.Connect(ctx, repoConf); err != nil {
        ...
	}

	return &Adapter{
		mongo:       mongo,
		mongoClient: mongo.GetClient(),
	}, nil
}

// UpdateEmails using mongo's BulkWrite
func (a *Adapter) UpdateEmails(ctx context.Context) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), MongoOpName)
	defer span.Finish()
	span.SetTag("operation", "BulkWrite")

	firstUpdate := bson.D{{"$set", bson.D{{"email", "firstEmail@example.com"}}}}
	secondUpdate := bson.D{{"$set", bson.D{{"email", "secondEmail@example.com"}}}}
	models := []mongo.WriteModel{
		mongo.NewUpdateOneModel().SetFilter(bson.D{{"_id", "123"}}).SetUpdate(firstUpdate).SetUpsert(true),
		mongo.NewUpdateOneModel().SetFilter(bson.D{{"_id", "456"}}).SetUpdate(secondUpdate).SetUpsert(true),
	}
	opts := options.BulkWrite().SetOrdered(false)
	res, err := a.mongoClient.BulkWrite(ctx, models, opts)
	if err != nil {
		ext.Error.Set(span, true)
		return err
	}
	
	fmt.Printf("inserted %v and deleted %v documents\n", res.InsertedCount, res.DeletedCount)
}
```

### TearDown:

Disconnects the client from mongo.

### Multi Collection

The library also support all the above capabilities while allowing dynamic change of the worked upon collection between operations. 

To achieve this, create a `CollectionlessMongo`, using `NewCollectionlessMongo` instead of `NewClient`.
All previous functions exists for this struct. The difference is that each function expects a collection alongside its other input arguments.

Example:
```go
    m := NewCollectionlessMongo()

	conf := MongoConfig{
		Host:       host,
		Port:       port,
		Database:   testName,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.Connect(ctx, conf); err != nil {
		...
	}

    item := Person{
		Name:           "Elad",
		Age:            "young",
	}

	id, err := m.AddOne(context.Background(), "my-collection", item)
    ...

```

One additional function exists for this struct:

### CreateCollection:
Given a collection name the collection is created if it does not already exist.

### BulkWrite:

update documents in db in bulks according to the writeModels that has passed to the function
in an ordered or unordered fashion according to ordered parameter
docs - https://www.mongodb.com/docs/manual/reference/method/db.collection.bulkWrite/

| Name        | Description                                                                                           |                                                                                                                                 
|-------------|-------------------------------------------------------------------------------------------------------|
| ordered     | If true, no writes will be executed after one fails. The default value is true.                       |   
| writeModels | the write models that will be executed in bulk write operation.                                       |   
 |             | docs - https://www.mongodb.com/docs/manual/reference/method/db.collection.bulkWrite/#write-operations | 
