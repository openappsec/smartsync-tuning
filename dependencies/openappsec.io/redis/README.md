# redis

A package aimed to give convenient access to the official redis golang driver (go-redis).

## Capabilities:

### NewClient:

Creates a new, uninitialized client. To render the client usable call the `ConnectToStandalone` or `ConnectToSentinel` method. 

### NewCMDClient:
Create a new instance initialized with the provided redis.Cmdable object. It allows you access to the package functions which run commands on an initialized redis instance.


### ConnectToStandalone:

This function accepts a context and a struct with configuration for connection to **standalone** redis. Asserts connection with healthcheck and return error upon failed connection. 

The fields that can be passed in the configuration can be seen in the table below.<br>

| Variable         |  Type         | Description                                                                                                                                             |
|------------------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| Address          | string        | the address of the redis server to which you'd like to connect.                                                                                         |
| Password         | string        | This field specifies the password with which to connect.                                                                                                |
| TLSEnabled       | boolean       | When this field set to true, TLS will be negotiated.                                                                                                    |

### ConnectToSentinel:

This function accepts a context and a struct with configuration for connection to **sentinel** redis.  Asserts connection with healthcheck and return error upon failed connection. 

The fields that can be passed in the configuration can be seen in the table below.<br>

| Variable         |  Type            | Description                                                                                                                                             |
|------------------|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| Addresses        | slice of strings | A seed list of host:port addresses of sentinel nodes.                                                                                                   |
| Password         | string           | This field specifies the password with which to connect.                                                                                                |
| MasterName       | string           | This field specifies the master name.                                                                                                                   |
| TLSEnabled       | boolean          | When this field set to true, TLS will be negotiated.                                                                                                    |

### HealthCheck:

Exposes a healthcheck function to be used in various readiness checks. This healthcheck executes a PING operation to the redis server.

### HSet:

Accepts context, a key and a value (as a hash map) for performing redis `HSet` operation.<br>
If one (or more) of the fields of the hash map already exists, it is overwritten.<br>
Upon success a nil error is returned. 

### HGetAll:

Accepts context and a key for performing redis `HGetAll` operation.<br>
If the given key does not exist, or has no fields, a ClassNotFound error is returned. 
Upon success the result is returned as a `map[string]string` and a nil error is returned. 

### Set:

Accepts context, a key, a value (as an `interface`) and TTL (as `time.Duration`) for performing redis `Set` operation.<br>
If key already holds a value, it is overwritten, regardless of its type.<br>
Zero TTL means the key has no expiration time.<br>
Upon success a nil error is returned.

### SetMulti:
Sets multiple records and returns the keys that were set, and the maximum ttl of all records.

### SetAdd:
Adds the specified members to the set stored at key, returns the number of elements
that were added to the set, and an error if any occurred.

### IsExistInSetMulti
IsExistInSetMulti checks whether each member is a member of the set stored at key.
Returns a slice representing the membership of the given 'values', in the same order as they are requested.
Note that an empty slice will be returned either when the given `key` is existing but without the given `values`,
or when `key` doesn't exist at all.

### SetIfNotExist:

Accepts context, a key, a value (as an `interface`) and TTL (as `time.Duration`) for performing redis `SetNX` operation.<br>
If key already holds a value, it returns false and does not override it.<br>
Zero TTL means the key has no expiration time.<br>
Upon success a true value and a nil error is returned.

### SetRecordsToSets:
Sets all records, for each set key in setsKeys it adds all records' keys and updates the set's ttl

### SetTTL:
Sets the TTL of key with the given ttl.
Returns true if successfully set the new TTL for key, or false and an error otherwise.

### GetTTL:
returns the TTL of key if successful, or 0 and an error otherwise.

### SetAddToArray:

Accepts context, a key, a value (as an `interface`) for performing redis `SAdd` operation.<br>
If the key exists adds the value to the current array values, else create a new record.<br>
Upon success returns the number of set values and a nil error.

### GetArrayMembers:

Accepts context and a key for performing redis `SMembers` operation.<br>
Upon success the result is returned as a []`string` and a nil error is returned.<br>
If the record does not exist returns empty response.

### GetStringArrayMembers:

Accepts context and a key for performing redis `SMembers` operation.<br>
Upon success the result is returned as a []`string` and a nil error is returned.<br>
The return value is striped from the " " for every string value.
If the record does not exist returns empty response.

### Get:

Accepts context and a key for performing redis `Get` operation.<br>
If the given key does not exist, a `ClassNotFound` error is returned. <br>
Upon success the result is returned as a `string` and a nil error is returned. 

### Incr:

Accepts context, and a key, for performing redis `Incr` operation.<br>
If the key does not exist, it is set to 0 before performing the operation.<br>
Upon success return the value of key after the increment.

### IncrByFloat:

Accepts context, a key and a value (as a `float64`), for performing redis `IncrByFloat` operation.<br>
If the key does not exist, it is set to 0 before performing the operation.<br>
Upon success return the value of key after the increment.

### GetByPattern (NOT FOR USE IN PRODUCTION - See [How To Section](#how-to)):

Accepts context and a pattern key for performing redis `KEYS` operation.<br>
If the given pattern key does not match any key, a `ClassNotFound` error is returned. <br>
Upon success the matching values is returned as a list of `string` and a nil error is returned.

### GetAllValues:

Accepts context and a list of keys for performing redis `MGet` operation.<br>
If a given key does not exist it's ignored. <br>
Upon success a list of values returned as a `[]string` and a nil error is returned. 

### GetAllExistingValuesAndMissingKeys:

Accepts context and a list of keys for performing redis `MGet` operation.<br>
It returns a struct containing:
1. A list of all the existing keys' values (returned as a `[]string`) 
2. A list of all the missing keys (returned as a `[]string`) 

### WatchTransaction:

Accepts context, keys, arguments, transaction attempts and the transaction function<br>
for performing redis transaction using `Watch` operation.<br>
If the transaction fails, return error.

### DELETE

Accepts context and a list of keys for performing `DEL` operation.<br>
If a given key does not found it's ignored.<br>
Returns the number of keys that were removed.

### DeleteByPattern (NOT FOR USE IN PRODUCTION - See [How To Section](#how-to)):

Accepts context and a pattern for performing `SCAN` and `DEL` operation by iterating the scan result.<br>
If a given pattern does not match any key it's ignored.<br>
Returns the number of total keys found, and the number of keys that were actually removed.

### SaveBulk:

Accepts context and a list of redis `Record` for performing redis `pipeline exec` operation which save records in bulk.<br>
It returns an error if presents, else nil.

### SELECT

Accepts context and a db index selects the database of the client's connection with the index.<br>
Returns the error if occurred.

### Expire

Accepts context, key and expiration to expire the key in the given expiration time (minimal supported expiration time is 1s).<br>
Returns a boolean indicates whether the expiration was set

### TearDown:

Disconnects the client from redis.

### RemoveValuesFromSet

Remove values from a set and returns the number of deleted elements.

### CountNumberOfValuesInASet

Returns the number of elements in set (in O(1))

### SetCacheMaxMemory

Reset the cache max memory size using ConfigSet.

# How To:
## Avoid GetKeysByPattern and DeleteByPattern functions:
Since these functions use the [KEYS command](https://redis.io/commands/keys) which is not recommended for use in production,
we offer a different approach to achieve the same functionality with better performance.

### The core idea:
Keep a key of holding a [Set](https://redis.io/topics/data-types#sets) of keys, each key matches the desired pattern.

#### Get keys by a pattern
1. Gets the key to the Set of keys - using [GetStringArrayMembers function](#getstringarraymembers)
#### Get all the values of keys matching a pattern
Use function [GetAllExistingValuesAndMissingKeys](#getallexistingvaluesandmissingkeys) which does the following:
1. Gets the values of each key from the Set
2. Returns the keys in the set which no longer exist for later deletion

#### Set keys and add them to Sets
In case you'd like to atomically set a key and add it to a set of keys which match a pattern,
use function [SetRecordsToSets](#setrecordstosets) which does the following:
1. Sets the key of each record
2. Adds each key to each Set (each Set represents a pattern)
3. Extends the TTL of each Set

Note: Please refer to the documentation of this function for more details.

