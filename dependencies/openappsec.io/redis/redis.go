package redis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/opentracing/opentracing-go"
	"github.com/rueian/rueidis"

	"openappsec.io/errors"
	"openappsec.io/log"
	"openappsec.io/tracer"
)

const (
	redisOpName = "golang-redis"
	// KeyExistsLabel is the error label for errors of operations that failed due to a key already existing.
	KeyExistsLabel = "KeyExistsLabel"
)

// Adapter for redis which holds the client.
type Adapter struct {
	client      *redis.Client
	cmdable     redis.Cmdable
	stackClient rueidis.Client
}

// SentinelConf struct represents the sentinel redis configuration
type SentinelConf struct {
	Addresses  []string
	Password   string
	TLSEnabled bool
	MasterName string
	DB         int
}

// StandaloneConf struct represents the standalone redis configuration
type StandaloneConf struct {
	Address    string
	Password   string
	TLSEnabled bool
	DB         int
}

// ExistingValuesAndMissingKeys struct is the response of function GetAllExistingValuesAndMissingKeys.
// It contains a list of all the existing keys' values and a list of all the missing keys
type ExistingValuesAndMissingKeys struct {
	ExistingValues []string
	MissingKeys    []string
}

// Record is a struct containing a record's data when being set in redis.
type Record struct {
	Key   string
	Value interface{}
	TTL   time.Duration
	// SetIfNotExists set to true to set using Adapter.SetIfNotExist, otherwise use Adapter.Set.
	SetIfNotExists bool
}

// SetMultiResponse is the response of function SetMulti.
type SetMultiResponse struct {
	Keys   []string
	MaxTTL time.Duration
}

// NewClient returns a redis adapter.
func NewClient() *Adapter {
	return &Adapter{}
}

// NewCMDClient returns a redis adapter without a client and with the provided redis.Cmdable
func NewCMDClient(cmd redis.Cmdable) *Adapter {
	return &Adapter{
		cmdable: cmd,
	}
}

// ConnectToSentinel connects to sentinel redis.
func (a *Adapter) ConnectToSentinel(ctx context.Context, c SentinelConf) error {
	span := tracer.GlobalTracer().StartSpan(redisOpName)
	defer span.Finish()
	span.SetTag("operation", "ConnectToSentinel")

	log.WithContext(ctx).Infoln("Creating new Redis Sentinel client")
	var options redis.FailoverOptions
	var jsonClientOptions rueidis.ClientOption
	options.SentinelAddrs = c.Addresses
	jsonClientOptions.InitAddress = c.Addresses
	options.MasterName = c.MasterName
	jsonClientOptions.Sentinel.MasterSet = c.MasterName
	options.Password = c.Password
	jsonClientOptions.Password = c.Password
	options.DB = c.DB
	jsonClientOptions.SelectDB = c.DB
	if c.TLSEnabled {
		options.TLSConfig = &tls.Config{}
		jsonClientOptions.TLSConfig = &tls.Config{}
	}

	a.client = redis.NewFailoverClient(&options)
	a.cmdable = a.client

	// initialize a json client as well in case we are using the stack adapter
	jsonClient, err := rueidis.NewClient(jsonClientOptions)
	if err != nil {
		return errors.Wrapf(err, "Failed to create redis stack client")
	}

	a.stackClient = jsonClient

	// make sure connection can be made
	if _, err := a.HealthCheck(ctx); err != nil {
		*a = Adapter{}
		return errors.Wrapf(err, "Connection to redis sentinel could not be made")
	}

	return nil
}

// ConnectToStandalone connects to standalone redis.
func (a *Adapter) ConnectToStandalone(ctx context.Context, c StandaloneConf) error {
	span := tracer.GlobalTracer().StartSpan(redisOpName)
	defer span.Finish()
	span.SetTag("operation", "ConnectToStandalone")

	log.WithContext(ctx).Infoln("Creating new Redis Standalone client")
	var options redis.Options
	var jsonClientOptions rueidis.ClientOption
	options.Addr = c.Address
	jsonClientOptions.InitAddress = []string{c.Address}
	options.Password = c.Password
	jsonClientOptions.Password = c.Password
	options.DB = c.DB
	jsonClientOptions.SelectDB = c.DB
	if c.TLSEnabled {
		options.TLSConfig = &tls.Config{}
		jsonClientOptions.TLSConfig = &tls.Config{}
	}

	a.client = redis.NewClient(&options)
	a.cmdable = a.client

	jsonClient, err := rueidis.NewClient(jsonClientOptions)
	if err != nil {
		return errors.Wrapf(err, "Failed to create redis stack client")
	}

	a.stackClient = jsonClient

	// make sure connection can be made
	if _, err := a.HealthCheck(ctx); err != nil {
		*a = Adapter{}
		return errors.Wrapf(err, "Connection to redis standalone could not be made")
	}

	return nil
}

// TearDown gracefully ends the lifespan of a redis repository instance. Closing all connections.
func (a *Adapter) TearDown(ctx context.Context) error {
	span := tracer.GlobalTracer().StartSpan(redisOpName)
	defer span.Finish()
	span.SetTag("operation", "TearDown")

	log.WithContext(ctx).Infoln("Closing Redis client connections...")
	if err := a.client.WithContext(ctx).Close(); err != nil {
		return errors.Wrap(err, "Failed to close Redis client connections").SetClass(errors.ClassInternal)
	}

	a.stackClient.Close()

	return nil
}

// HealthCheck PINGs the Redis server to check if it is accessible and alive.
func (a *Adapter) HealthCheck(ctx context.Context) (string, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "HealthCheck")

	checkName := "Redis PING Test"
	if pong, err := a.client.WithContext(ctx).Ping(ctx).Result(); err != nil || pong != "PONG" {
		if err == nil {
			err = errors.Errorf("Ping response: %s", pong)
		}
		return checkName, errors.Wrap(err, "Cannot reach Redis, failing health check").SetClass(errors.ClassInternal)
	}

	pingCommand := a.stackClient.B().Ping().Build()
	if res := a.stackClient.Do(ctx, pingCommand); res.Error() != nil {
		return checkName, errors.Wrapf(res.Error(), "Json client cannot reach Redis, failing health check")
	}

	return checkName, nil
}

// HGetAll queries redis with 'HGETALL' command, and put the result in result map.
func (a *Adapter) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "HGetAll")

	res, err := a.cmdable.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, errors.Wrap(err, "Redis HGetAll operation returned an error").SetClass(errors.ClassInternal)
	}
	if len(res) < 1 {
		return nil, errors.Errorf("key (%s) doesn't exist or has no fields", key).SetClass(errors.ClassNotFound)
	}

	return res, nil
}

// HSet sets value/s in hash key using 'HSET' command.
func (a *Adapter) HSet(ctx context.Context, key string, values map[string]interface{}) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "HSet")

	res := a.cmdable.HSet(ctx, key, values)
	if res.Err() != nil {
		return errors.Wrap(res.Err(), "Redis HSet operation returned an error")
	}

	return nil
}

// HIncrBy Increments the number stored at field of hash map key by given value.
// If the hash map does not exist, it created a new hash map.
// If the field of the hash map does not exist, it's set to 0 before the operation is performed.
// Returns the value of key after the increment.
func (a *Adapter) HIncrBy(ctx context.Context, key, field string, incr int64) (int64, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "HIncrBy")

	res := a.cmdable.HIncrBy(ctx, key, field, incr)
	if res.Err() != nil {
		return int64(0), errors.Wrap(res.Err(), "Redis HIncrBy operation returned an error")
	}

	return res.Val(), nil
}

// Set sets 'key' to hold 'value' using 'SET' command with ttl.
// Zero ttl means the key has no expiration time.
func (a *Adapter) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "Set")

	data, err := json.Marshal(value)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal value")
	}

	res := a.cmdable.Set(ctx, key, data, ttl)
	if res.Err() != nil {
		return errors.Wrap(res.Err(), "Redis Set operation returned an error")
	}

	return nil
}

// SetIfNotExist sets 'key' to hold 'value' if key does not exist using 'SETNX' command with ttl.
// Zero ttl means the key has no expiration time.
// first return value indicates if the key was set
func (a *Adapter) SetIfNotExist(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetIfNotExist")

	data, err := json.Marshal(value)
	if err != nil {
		return false, errors.Wrap(err, "Failed to marshal value")
	}

	res := a.cmdable.SetNX(ctx, key, data, ttl)
	if res.Err() != nil {
		return false, errors.Wrap(res.Err(), "Redis SetNX operation returned an error")
	}

	return res.Val(), nil
}

// SetMulti sets multiple records (by calling the Set or SetIfNotExist function) and returns the keys that were set,
// and the maximum ttl of all set records. Records' TTL must be positive for it to be set.
// Returns an error on first non-positive TTL occurrence and returns the records that were set until the first occurrence.
// Returns error with label KeyExistsLabel if tried setting a record with Record.SetIfNotExists set to true and the record exists.
func (a *Adapter) SetMulti(ctx context.Context, records ...Record) (SetMultiResponse, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetMulti")

	res := SetMultiResponse{
		Keys: make([]string, 0, len(records)),
	}

	for _, record := range records {
		if record.TTL <= 0 {
			return res, errors.Errorf("Failed to set record with key %s, value: %#v, ttl: %d. Got non-positive TTL", record.Key, record.Value, record.TTL)
		}

		if record.SetIfNotExists {
			isSet, err := a.SetIfNotExist(ctx, record.Key, record.Value, record.TTL)
			if err != nil {
				return res, errors.Wrapf(err, "Failed to set if record doesn't exist with key: %s, value: %#v, ttl: %d", record.Key, record.Value, record.TTL)
			}

			if !isSet {
				return res, errors.Errorf("Failed to set if record key already exists with key: %s, value: %#v, ttl: %d", record.Key, record.Value, record.TTL).SetLabel(KeyExistsLabel)
			}
		} else if err := a.Set(ctx, record.Key, record.Value, record.TTL); err != nil {
			return res, errors.Wrapf(err, "Failed to set record with key: %s, value: %#v, ttl: %d", record.Key, record.Value, record.TTL)
		}

		res.Keys = append(res.Keys, record.Key)

		if record.TTL > res.MaxTTL {
			res.MaxTTL = record.TTL
		}
	}

	return res, nil
}

// SetAddToArray sets 'key' to hold array 'value' using 'SAdd' command.
// If the record exists adds the value to the current array values, else create a new record.
// First return value indicates if the key was set
func (a *Adapter) SetAddToArray(ctx context.Context, key string, value interface{}) (int, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetAddToArray")

	data, err := json.Marshal(value)
	if err != nil {
		return 0, errors.Wrap(err, "Failed to marshal value")
	}

	res := a.cmdable.SAdd(ctx, key, data)
	if res.Err() != nil {
		return 0, errors.Wrap(res.Err(), "Redis SAdd operation returned an error")
	}

	return int(res.Val()), nil
}

// IsExistInSetMulti gets 'key' of a set and 'values' and checks the existence of the 'values' in the given `key`
// using redis command `SMISMEMBER`.
// Returns a slice representing the membership of the given 'values', in the same order as they are requested.
// Note that an empty slice will be returned either when the 'key' is existing but without the given 'values',
// or when 'key' doesn't exist at all.
func (a *Adapter) IsExistInSetMulti(ctx context.Context, key string, values ...interface{}) ([]bool, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "IsExistInSetMulti")

	var err error
	valuesBytes := make([]interface{}, len(values))
	for idx, value := range values {
		valuesBytes[idx], err = json.Marshal(value)
		if err != nil {
			return []bool{}, errors.Wrap(err, "Failed to marshal value")
		}
	}

	res := a.cmdable.SMIsMember(ctx, key, valuesBytes)
	if res.Err() != nil {
		return []bool{}, errors.Wrap(res.Err(), "Redis SMIsMember operation returned an error")
	}

	return res.Val(), nil
}

// SetAdd adds the specified members to the set stored at key, returns the number of elements
// that were added to the set, and an error if any occurred.
func (a *Adapter) SetAdd(ctx context.Context, key string, members ...interface{}) (int, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetAdd")

	sumAdded := 0
	for _, member := range members {
		nAdded, err := a.SetAddToArray(ctx, key, member)
		if err != nil {
			return sumAdded, errors.Wrap(err, "Redis SAdd operation returned an error")
		}

		sumAdded += nAdded
	}

	return sumAdded, nil
}

// SetRecordsToSets sets all records, for each set key in setsKeys it adds all records' keys and updates the set's ttl.
// The usage for this function is to atomically set multiple records, and add the records keys to each set of setKeys.
// For example: Set [{Key: "some-record-key", Value: ...}] -> SAdd "some-set-key" "some-record-key" -> update "some-key-set" TTL.
// We are adding the maximum TTL of all records to each of the sets' current TTL, since:
// (1) A Set's TTL should always exist
// (2) Persistency - Kept by making sure a Set's TTL is an upper bound on all the keys' TTLs that it holds.
// The operation is using a transaction.
//
// Note: Forces use of Set instead of SetIfNotExist. If caller of this function wants to set records if they don't exist
// they must implement a locking mechanism wrapping the call to SetRecordsToSets.
func (a *Adapter) SetRecordsToSets(ctx context.Context, records []Record, setsKeys []string) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetRecordsToSets")

	recordsCopy := make([]Record, len(records))
	recordsKeys := make([]interface{}, 0, len(records))

	copy(recordsCopy, records)
	for i := range recordsCopy {
		// This is to "trick" SetMulti that runs inside the transaction to not give us false errors,
		// because we don't have a response in the transaction yet.
		recordsCopy[i].SetIfNotExists = false
		recordsKeys = append(recordsKeys, recordsCopy[i].Key)
	}

	// Get the sets' TTL before the transaction starts to know the TTL that needs to be set inside the transaction.
	// This is an over estimation since the TTL always goes down.
	// In case a set is expired between this part and the transaction's start, it's still working as intended since
	// the set always has a TTL that's equals or greater than its referenced records' maximum TTL.
	setsTTL := make(map[string]time.Duration, len(setsKeys))
	for _, setKey := range setsKeys {
		ttl, err := a.GetTTL(ctx, setKey)
		if err != nil {
			return errors.Wrapf(err, "Failed to get TTL for set key %s", setKey)
		}

		// The set's TTL could be -1 and since SetMulti guarantees maximum TTL to be positive,
		// then we need to fix the set's ttl to 0. For example when first created ttl = -1, maxTTL = 4 -> new ttl = 3
		// Or the set does not exist yet, in that case its ttl would be -2.
		if ttl <= 0 {
			ttl = 0
		}

		setsTTL[setKey] = ttl
	}

	// Execute the transaction
	_, err := a.cmdable.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		txAdapter := NewCMDClient(pipe)

		// 1. Set all records and get their keys and maximum TTL of all records
		setMultiRes, err := txAdapter.SetMulti(ctx, recordsCopy...)
		if err != nil {
			return err
		}

		// 2. For each set key add all keys that were set in step 1,
		// and extend the set's TTL by the maximum TTL from step 1.
		for _, setKey := range setsKeys {
			// 2.1 Add all keys to the current set in the iteration
			if _, err := txAdapter.SetAdd(ctx, setKey, recordsKeys...); err != nil {
				return err
			}

			// 2.2 Set current set's TTL to be extended by the maximum TTL from step 1.
			newSetTTL := setsTTL[setKey] + setMultiRes.MaxTTL
			if _, err := txAdapter.SetTTL(ctx, setKey, newSetTTL); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return errors.Wrap(err, "Failed transaction execution")
	}

	return nil
}

// GetTTL returns the TTL of key if successful, or 0 and an error otherwise.
// If no expiration is set for key, returns -1.
func (a *Adapter) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "GetTTL")

	ttl, err := a.cmdable.TTL(ctx, key).Result()
	if err != nil {
		return 0, errors.Wrap(err, "Redis TTL operation returned an error")
	}

	return ttl, nil
}

// SetTTL sets the TTL of key with the given ttl.
// Returns true if successfully set the new TTL for key, or false and an error otherwise.
// Returns false and nil error if the key doesn't exist.
func (a *Adapter) SetTTL(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetTTL")

	isSet, err := a.cmdable.Expire(ctx, key, ttl).Result()
	if err != nil {
		return false, errors.Wrap(err, "Redis EXPIRE operation returned an error")
	}

	return isSet, nil
}

// GetArrayMembers get the array of values saved while doing 'SMembers'.
func (a *Adapter) GetArrayMembers(ctx context.Context, key string) ([]string, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "GetArrayMembers")

	res := a.cmdable.SMembers(ctx, key)
	if res.Err() != nil {
		return []string{}, errors.Wrap(res.Err(), "Redis SMembers operation returned an error")
	}

	return res.Val(), nil
}

// GetStringArrayMembers get the array of values saved while doing 'SMembers' and return result for set string values.
func (a *Adapter) GetStringArrayMembers(ctx context.Context, key string) ([]string, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "GetStringArrayMembers")

	res, err := a.GetArrayMembers(ctx, key)
	if err != nil {
		return []string{}, errors.Wrap(err, "GetStringArrayMembers operation returned an error")
	}

	// striping all the "" from the string values
	for i, item := range res {
		value := strings.TrimPrefix(item, "\"")
		value = strings.TrimSuffix(value, "\"")
		res[i] = value
	}

	return res, nil
}

// Get queries redis with 'GET' command and returns the result.
func (a *Adapter) Get(ctx context.Context, key string) (string, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "Get")

	res, err := a.cmdable.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", errors.Wrapf(err, "key (%s) doesn't exist", key).SetClass(errors.ClassNotFound)
	} else if err != nil {
		return "", errors.Wrap(err, "Redis Get operation returned an error").SetClass(errors.ClassInternal)
	}

	return res, nil
}

// GetKeysByPattern queries redis with 'KEYS' command, return all keys that match the received pattern.
// if the pattern doesn't match any key, return not found error.
func (a *Adapter) GetKeysByPattern(ctx context.Context, keysPattern string) ([]string, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "GetKeysByPattern")

	res, err := a.cmdable.Keys(ctx, keysPattern).Result()
	if err != nil {
		return nil, errors.Wrap(err, "Redis KEYS operation returned an error").SetClass(errors.ClassInternal)
	}

	if len(res) < 1 {
		return nil, errors.Errorf("pattern (%s) doesn't match any key in cache", keysPattern).SetClass(errors.ClassNotFound)
	}

	return res, nil
}

// GetAllValues queries redis with 'MGET' command and returns a list of values at the specified keys.
// if a given key is not exist, it's ignored.
func (a *Adapter) GetAllValues(ctx context.Context, keys ...string) ([]string, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "GetAllValues")

	res, err := a.cmdable.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, errors.Wrap(err, "Redis MGET operation returned an error").SetClass(errors.ClassInternal)
	}

	strSliceRes := make([]string, 0, len(res))
	for _, val := range res {
		// ignore not found keys
		if val == nil {
			continue
		}
		if strVal, ok := val.(string); ok {
			strSliceRes = append(strSliceRes, strVal)
		} else {
			log.WithContext(ctx).Warnf("GetAllValues operation failed to convert a value (%v) to string, skipping this value", val)
		}
	}

	return strSliceRes, nil
}

// GetAllExistingValuesAndMissingKeys queries redis with 'MGET' command and returns:
// 1. A list of all existing values at the specified keys.
// 2. A list of all the keys which were missing
func (a *Adapter) GetAllExistingValuesAndMissingKeys(ctx context.Context, keys ...string) (ExistingValuesAndMissingKeys, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "GetAllExistingAndMissingValues")

	res, err := a.cmdable.MGet(ctx, keys...).Result()
	if err != nil {
		return ExistingValuesAndMissingKeys{}, errors.Wrap(err, "Redis MGET operation returned an error").SetClass(errors.ClassInternal)
	}

	strSliceValRes := make([]string, 0, len(res))
	missingKeys := make([]string, 0)
	valueToStrFailures := make(map[string]interface{}, 0)
	for i, val := range res {
		if val == nil {
			missingKeys = append(missingKeys, keys[i])
			continue
		}

		if strVal, ok := val.(string); ok {
			strSliceValRes = append(strSliceValRes, strVal)
		} else {
			valueToStrFailures[keys[i]] = val
		}
	}

	if len(valueToStrFailures) > 0 {
		log.WithContext(ctx).Warnf("GetAllExistingValuesAndMissingKeys failed to convert the following values to string (not included in final res): %+v", valueToStrFailures)
	}

	return ExistingValuesAndMissingKeys{ExistingValues: strSliceValRes, MissingKeys: missingKeys}, nil
}

// Delete deletes the given keys from redis, ignored if not exists.
func (a *Adapter) Delete(ctx context.Context, keys ...string) (int64, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "DEL")

	res, err := a.cmdable.Del(ctx, keys...).Result()
	if err != nil {
		return int64(0), errors.Wrap(err, "Redis DEL operation returned an error").SetClass(errors.ClassInternal)
	}

	return res, nil
}

// DeleteByPattern deletes the keys that match the given pattern from redis, ignore if not exist.
// returns the number of keys found and number of keys deleted.
func (a *Adapter) DeleteByPattern(ctx context.Context, pattern string) (int64, int64, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "DeleteByPattern")

	var totalCount, delCount int64
	iter := a.cmdable.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		totalCount++
		err := a.client.Del(ctx, iter.Val()).Err()
		if err != nil {
			log.WithContext(ctx).Debugf("Redis DEL operation (key = %s) returned an error, skipping key: %s", iter.Val(), err.Error())
			continue
		}
		delCount++
	}
	if err := iter.Err(); err != nil {
		return int64(0), int64(0), errors.Wrap(err, "Redis SCAN iterator returned an error").SetClass(errors.ClassInternal)
	}

	return totalCount, delCount, nil
}

// Incr Increments the number stored at key by one. If the key does not exist, it is set to 0 before performing the operation.
// Returns the value of key after the increment.
func (a *Adapter) Incr(ctx context.Context, key string) (int64, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "Incr")

	res := a.cmdable.Incr(ctx, key)
	if res.Err() != nil {
		return int64(0), errors.Wrap(res.Err(), "Redis Incr operation returned an error")
	}

	return res.Val(), nil
}

// IncrByFloat Increment the floating point stored at key by the specified value.
// If the key does not exist, it is set to 0 before performing the operation. Returns the value of key after the increment.
func (a *Adapter) IncrByFloat(ctx context.Context, key string, value float64) (float64, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "IncrByFloat")

	res := a.cmdable.IncrByFloat(ctx, key, value)
	if res.Err() != nil {
		return float64(0), errors.Wrap(res.Err(), "Redis IncrByFloat operation returned an error")
	}

	return res.Val(), nil
}

// WatchTransaction creates a transaction using the watch function over the receiving keys.
// The function gets a transaction function to run the watch on, and performs retry if needed as the transAttempts number.
// The function gets keys and arguments and pass them to the transaction function
func (a *Adapter) WatchTransaction(ctx context.Context, keys []string, args []string, transAttempts int, transFunc func(ctx context.Context, keys []string, args ...string) func(tx *redis.Tx) error) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "WatchTransaction")

	var transErr error
	for i := 0; i < transAttempts; i++ {
		err := a.client.Watch(ctx, transFunc(ctx, keys, args...), keys...)
		// success
		if err == nil {
			return nil
		}

		transErr = err
	}

	return transErr
}

// Select selects the database of the client's connection with the index.
func (a *Adapter) Select(ctx context.Context, dbIndex int) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "Select")

	dbIndexStr := strconv.Itoa(dbIndex)
	if err := a.client.Do(ctx, "SELECT", dbIndexStr).Err(); err != nil {
		return errors.Wrap(err, "Redis SELECT operation returned an error")
	}

	return nil
}

// Expire expires a given key in a given time
// Minimal supported expiration value is 1s
// Returns a boolean indicates whether the expiration was set
func (a *Adapter) Expire(ctx context.Context, key string, expiration time.Duration) (bool, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "Expire")

	res, err := a.client.Expire(ctx, key, expiration).Result()
	if err != nil {
		return false, errors.Wrap(err, "Redis EXPIRE operation returned an error")
	}

	return res, nil
}

// RemoveValuesFromSet removes the provided values from the set under the provided key.
// Returns the number of deleted members.
// In case the key doesn't hold a set - returns an error.
func (a *Adapter) RemoveValuesFromSet(ctx context.Context, key string, valuesToRemove ...interface{}) (int64, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "RemoveValuesFromSet")

	marshaledValToRemove := make([]interface{}, 0, len(valuesToRemove))
	for _, val := range valuesToRemove {
		valByte, err := json.Marshal(val)
		if err != nil {
			return 0, errors.Wrapf(err, "Failed to marshal value to remove from set: %+v", val)
		}

		marshaledValToRemove = append(marshaledValToRemove, valByte)
	}

	removedCount, err := a.cmdable.SRem(ctx, key, marshaledValToRemove...).Result()
	if err != nil {
		return 0, errors.Wrapf(err, "Failed to remove values from key (%s)", key)
	}

	return removedCount, nil
}

// CountNumberOfValuesInASet counts the number of elements in a set.
// Returns 0 is the key doesn't exist
func (a *Adapter) CountNumberOfValuesInASet(ctx context.Context, key string) (int64, error) {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "CountNumberOfValuesInASet")

	return a.cmdable.SCard(ctx, key).Result()
}

// SetCacheMaxMemory reset the cache max memory size
func (a *Adapter) SetCacheMaxMemory(ctx context.Context, value string) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetCacheMaxMemory")

	if status := a.cmdable.ConfigSet(ctx, "maxmemory", value); status.Err() != nil {
		return errors.Wrapf(status.Err(), "Failed to set cache max memory to %s", value)
	}

	return nil
}

// SaveBulk save bulk of redis records to redis
func (a *Adapter) SaveBulk(ctx context.Context, records []Record) error {
	span, ctx := opentracing.StartSpanFromContextWithTracer(ctx, tracer.GlobalTracer(), redisOpName)
	defer span.Finish()
	span.SetTag("operation", "SetCacheMaxMemory")

	// initialize pipe
	pipe := a.cmdable.Pipeline()

	// set add records to pipe for future save
	for i := 0; i < len(records); i++ {
		data, err := json.Marshal(records[i].Value)
		if err != nil {
			return errors.Wrap(err, "Failed to marshal value")
		}

		pipe.SAdd(ctx, records[i].Key, data)
	}

	// flush pipe to redis
	_, err := pipe.Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed to save bulk to redis")
	}

	return nil
}
