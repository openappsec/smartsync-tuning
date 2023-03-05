package redis

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"openappsec.io/errors"
	"openappsec.io/redis"

	"openappsec.io/log"
)

const (
	// configuration keys
	confKeyRedisBase               = "redis."
	confKeyRedisAddress            = confKeyRedisBase + "address"
	confKeyRedisTLSEnabled         = confKeyRedisBase + "tlsEnabled"
	confKeyRedisSentinelMasterName = confKeyRedisBase + "sentinelMasterName"
	confKeyRedisSentinelPassword   = confKeyRedisBase + "sentinelPassword"
	confKeyLockTTL                 = confKeyRedisBase + "ttl."
	confKeyBlockingLockTTL         = confKeyLockTTL + "blocking"
	confKeyNonBlockingLockTTL      = confKeyLockTTL + "nonBlocking"

	lockKeyPrefix    = "waap-tuning_"
	nextRunnerPrefix = "waap-tuning-runner_"
	lockDBPrefix     = "waap-tuning-internal_"
)

// mockgen -destination mocks/mock_redis.go -package mocks -mock_names Repository=MockRedis,Configuration=MockRedisConfiguration -source ./internal/pkg/lock/redis/redis.go Redis

// Configuration exposes an interface of configuration related actions
type Configuration interface {
	GetString(key string) (string, error)
	GetDuration(key string) (time.Duration, error)
	GetInt(key string) (int, error)
	GetBool(key string) (bool, error)
}

// Redis library
type Redis interface {
	ConnectToSentinel(ctx context.Context, c redis.SentinelConf) error
	HealthCheck(ctx context.Context) (string, error)
	SetIfNotExist(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, keys ...string) (int64, error)
	TearDown(ctx context.Context) error
}

// Adapter represents the Redis adapter for sync data storage
type Adapter struct {
	r        Redis
	prefix   string
	lockTTL  time.Duration
	blockTTL time.Duration
}

// LockTenant acquire a lock for processing a tenant's data - returns true if successful
func (a *Adapter) LockTenant(ctx context.Context, tenantID string) bool {
	isSet, err := a.r.SetIfNotExist(ctx, a.prefix+tenantID, 1, a.lockTTL)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to lock resource for tenant: %v, err: %v", tenantID, err)
		// in case of error with the redis client allow all to get the lock to prevent blocking all processing
		return true
	}
	return isSet
}

// BlockingLockTenant tries to acquire a lock and blocking operation
// return error cancel if another process register for this lock
func (a *Adapter) BlockingLockTenant(ctx context.Context, tenantID string) error {
	log.WithContext(ctx).Infof("try to acquire blocking lock for tenant: %v", tenantID)
	isSet, err := a.r.SetIfNotExist(ctx, a.prefix+tenantID, 1, a.blockTTL)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to lock resource for tenant: %v, err: %v", tenantID, err)
		// in case of error with the redis client allow all to get the lock to prevent blocking all processing
		return err
	}
	if isSet {
		log.WithContext(ctx).Infof("acquired lock for key: %v", a.prefix+tenantID)
		return nil
	}

	runnerID := uuid.NewString()
	err = a.addRunnerToQueue(ctx, tenantID, runnerID)
	if err != nil {
		return err
	}
	defer a.popRunnerQueue(ctx, tenantID)
	for {
		if headRunner := a.peekRunnerQueue(ctx, tenantID); headRunner != runnerID {
			if headRunner == "" {
				return errors.New("empty queue")
			}
			time.Sleep(time.Millisecond * 30)
			continue
		} else {
			time.Sleep(time.Millisecond * 10)
		}
		log.WithContext(ctx).Infof("running id: %v", runnerID)
		isSet, err = a.r.SetIfNotExist(ctx, a.prefix+tenantID, 1, a.blockTTL)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to lock resource for tenant: %v, err: %v", tenantID, err)
			// in case of error with the redis client allow all to get the lock to prevent blocking all processing
			return err
		}
		if isSet {
			log.WithContext(ctx).Infof("acquired lock for key: %v", a.prefix+tenantID)
			return nil
		}
	}
}

// UnlockTenant unlocks the key for processing a tenant
func (a *Adapter) UnlockTenant(ctx context.Context, tenantID string) error {
	_, err := a.r.Delete(ctx, a.prefix+tenantID)
	return err
}

// NewAdapter returns a new Redis adapter for sync
func NewAdapter(ctx context.Context, redisAdapter Redis, config Configuration) (*Adapter, error) {
	adapt := &Adapter{r: redisAdapter}
	log.WithContext(ctx).Infoln("Get Redis Sentinel configuration")

	nonBlockingTTL, err := config.GetDuration(confKeyNonBlockingLockTTL)
	if err != nil {
		return nil, err
	}

	blockingTTL, err := config.GetDuration(confKeyBlockingLockTTL)
	if err != nil {
		return nil, err
	}

	adapt.prefix = lockKeyPrefix
	adapt.lockTTL = nonBlockingTTL
	adapt.blockTTL = blockingTTL

	address, err := config.GetString(confKeyRedisAddress)
	if err != nil {
		return nil, err
	}

	tlsEnable, err := config.GetBool(confKeyRedisTLSEnabled)
	if err != nil {
		return nil, err
	}

	masterName, err := config.GetString(confKeyRedisSentinelMasterName)
	if err != nil {
		return nil, err
	}

	password, err := config.GetString(confKeyRedisSentinelPassword)
	if err != nil {
		return nil, err
	}

	conf := redis.SentinelConf{
		Addresses:  []string{address},
		TLSEnabled: tlsEnable,
		MasterName: masterName,
		Password:   password,
	}
	log.WithContext(ctx).Infoln("Connect Redis Sentinel configuration")

	if err := adapt.r.ConnectToSentinel(ctx, conf); err != nil {
		return nil, errors.Wrap(err, "Failed to connect to sentinel redis")
	}

	return adapt, nil
}

// TearDown gracefully ends the lifespan of a redis repository instance. Closing all connections
func (a *Adapter) TearDown(ctx context.Context) error {
	return a.r.TearDown(ctx)
}

func (a *Adapter) lockDB(ctx context.Context, tenantID string) error {
	for {
		isSet, err := a.r.SetIfNotExist(ctx, lockDBPrefix+tenantID, 1, a.blockTTL)
		if err != nil {
			return err
		}
		if isSet {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
}

func (a *Adapter) unlockDB(ctx context.Context, tenantID string) error {
	_, err := a.r.Delete(ctx, lockDBPrefix+tenantID)
	return err
}
func (a *Adapter) addRunnerToQueue(ctx context.Context, tenantID string, runningID string) error {
	err := a.lockDB(ctx, tenantID)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to lock db operations. err: %v", err)
	}
	defer func() {
		err := a.unlockDB(ctx, tenantID)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to unlock db operations. err: %v", err)
		}
	}()
	isSet, err := a.r.SetIfNotExist(ctx, nextRunnerPrefix+tenantID, runningID, a.blockTTL)
	if err != nil {
		return err
	}
	if isSet {
		log.WithContext(ctx).Infof("first runner in list added: %v", runningID)
		return nil
	}
	currentQueue, err := a.r.Get(ctx, nextRunnerPrefix+tenantID)
	if err != nil {
		return err
	}
	currentQueue, err = strconv.Unquote(currentQueue)
	if err != nil {
		return err
	}
	currentQueue = fmt.Sprintf("%s;%s", currentQueue, runningID)

	log.WithContext(ctx).Infof("adding runner to list: %v", currentQueue)

	return a.r.Set(ctx, nextRunnerPrefix+tenantID, currentQueue, a.blockTTL)
}

func (a *Adapter) popRunnerQueue(ctx context.Context, tenantID string) {
	err := a.lockDB(ctx, tenantID)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to lock db operations. err: %v", err)
	}
	defer func() {
		err := a.unlockDB(ctx, tenantID)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to unlock db operations. err: %v", err)
		}
	}()
	currentQueue, err := a.r.Get(ctx, nextRunnerPrefix+tenantID)
	if err != nil {
		return
	}
	currentQueue, err = strconv.Unquote(currentQueue)
	if err != nil {
		return
	}

	queueSplit := strings.SplitN(currentQueue, ";", 2)
	if len(queueSplit) < 2 {
		log.WithContext(ctx).Infof("last runner in list: %v", queueSplit[0])
		_, err = a.r.Delete(ctx, nextRunnerPrefix+tenantID)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to delete next runners list. err: %v", err)
		}
		return
	}
	currentQueue = queueSplit[1]
	log.WithContext(ctx).Infof("pop runner in list: %v, new list: %v", queueSplit[0], currentQueue)
	err = a.r.Set(ctx, nextRunnerPrefix+tenantID, currentQueue, a.blockTTL)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to set next runners queue. err: %v", err)
	}
}

func (a *Adapter) peekRunnerQueue(ctx context.Context, tenantID string) string {
	err := a.lockDB(ctx, tenantID)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to lock db operations. err: %v", err)
	}
	defer func() {
		err := a.unlockDB(ctx, tenantID)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to unlock db operations. err: %v", err)
		}
	}()
	currentQueue, err := a.r.Get(ctx, nextRunnerPrefix+tenantID)
	if err != nil {
		return ""
	}
	currentQueue, err = strconv.Unquote(currentQueue)
	if err != nil {
		return ""
	}

	queueSplit := strings.SplitN(currentQueue, ";", 2)

	log.WithContext(ctx).Infof("current queue: %v, head: %v", currentQueue, queueSplit[0])

	return queueSplit[0]
}
