package bqadapter

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"sync"
	"time"

	"cloud.google.com/go/bigquery"
	"openappsec.io/errors"
	"openappsec.io/log"
	"google.golang.org/api/option"
)

const (
	confKeyGoogleCredentials = "GOOGLE_APPLICATION_CREDENTIALS"
	confKeyServiceAccount    = "DATATUBE_SERVICE_ACCOUNT_JSON"

	elpisPrefix = "org_"
	tablePrefix = "datatube_i2datatubeschemasecurityeventlogsv03_"
)

// Configuration used to get the configuration of the datatube dataset
type Configuration interface {
	GetString(key string) (string, error)
	IsSet(key string) bool
	GetDuration(key string) (time.Duration, error)
}

//NewBQAdapter creates a new driver
func NewBQAdapter(c Configuration) (*BQAdapter, error) {
	var cred []byte
	if !c.IsSet(confKeyGoogleCredentials) {
		credStr, err := c.GetString(confKeyServiceAccount)
		if err != nil || credStr == "" {
			return &BQAdapter{}, errors.New("service account credentials is not set")
		}
		credStrUnquote, err := strconv.Unquote(credStr)
		if err != nil {
			log.Warnf("failed to unquote credentials, %v", err)
			credStrUnquote = credStr
		}
		cred = []byte(credStrUnquote)
	} else {
		credPath, err := c.GetString(confKeyGoogleCredentials)
		if err != nil {
			log.Errorf("get string returned an error: %v", err)
		}
		jsonFile, err := os.Open(credPath)
		if err != nil {
			return &BQAdapter{}, errors.Wrapf(err, "failed to open credentials file %v", credPath)
		}
		defer func() {
			err := jsonFile.Close()
			log.Debugf("failed to close json file. error %v", err)
		}()

		cred, err = ioutil.ReadAll(jsonFile)
		if err != nil {
			return &BQAdapter{}, errors.Wrapf(err, "failed to read credentials file %v", credPath)
		}
	}
	var result map[string]interface{}
	err := json.Unmarshal(cred, &result)
	if err != nil {
		return &BQAdapter{}, errors.Wrapf(err, "failed to unmarshal credentials")
	}

	return &BQAdapter{credentials: cred, projectID: fmt.Sprint(result["project_id"])}, nil
}

//BQAdapter adapter driver for bigquery
type BQAdapter struct {
	credentials []byte
	projectID   string
	mutex       sync.Mutex
}

//Open creates a new connection to bigquery
func (adapter *BQAdapter) Open(_ string) (driver.Conn, error) {
	adapter.mutex.Lock()
	client, err := bigquery.NewClient(context.Background(),
		adapter.projectID,
		option.WithCredentialsJSON(adapter.credentials))
	adapter.mutex.Unlock()
	if err != nil {
		return &BQConn{}, err
	}
	return &BQConn{client: client}, nil
}
