package bqadapter

import (
	"context"
	"database/sql/driver"

	"cloud.google.com/go/bigquery"
)

//BQStmt a bq prepared statement
type BQStmt struct {
	query *bigquery.Query
}

//ExecContext executes a sql statement without a response
func (s *BQStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return nil, driver.ErrSkip
}

//QueryContext execute a query with a response
func (s *BQStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := s.query.Read(ctx)
	if err != nil {
		return &BQRows{}, err
	}
	return NewRows(rows), nil
}

//Close clear data
func (s *BQStmt) Close() error {
	s.query = nil
	return nil
}

//NumInput not implemented
func (s *BQStmt) NumInput() int {
	// disable sanity check
	return -1
}

func convertArgsToNamedValues(args []driver.Value) []driver.NamedValue {
	namedValArgs := make([]driver.NamedValue, len(args))
	for i, arg := range args {
		namedValArgs[i] = driver.NamedValue{Value: arg}
	}
	return namedValArgs
}

//Exec execute without a response
func (s *BQStmt) Exec(args []driver.Value) (driver.Result, error) {
	namedValArgs := convertArgsToNamedValues(args)
	return s.ExecContext(context.Background(), namedValArgs)
}

//Query execute with a response
func (s *BQStmt) Query(args []driver.Value) (driver.Rows, error) {
	namedValArgs := convertArgsToNamedValues(args)
	return s.QueryContext(context.Background(), namedValArgs)
}
