package bqadapter

import (
	"database/sql/driver"

	"cloud.google.com/go/bigquery"
)

//BQConn implements the driver.Conn interface
type BQConn struct {
	client *bigquery.Client
}

//Prepare a statement
func (bqc *BQConn) Prepare(query string) (driver.Stmt, error) {
	q := bqc.client.Query(query)
	return &BQStmt{query: q}, nil
}

//Close releases client and data
func (bqc *BQConn) Close() error {
	return bqc.client.Close()
}

//Begin a transaction - not implemented
func (bqc *BQConn) Begin() (driver.Tx, error) {
	return nil, driver.ErrSkip
}
