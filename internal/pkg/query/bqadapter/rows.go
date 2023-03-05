package bqadapter

import (
	"database/sql/driver"
	"io"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
)

//BQRows a row iterator
type BQRows struct {
	iterator *bigquery.RowIterator
	columns  []string
	rowIndex int
	row      []bigquery.Value
}

//NewRows creates a new rows from bq iterator
func NewRows(iterator *bigquery.RowIterator) *BQRows {
	return &BQRows{iterator: iterator}
}

//Columns return number of columns in a row
func (r *BQRows) Columns() []string {
	if len(r.columns) > 0 {
		return r.columns
	}
	if r.rowIndex == 0 {
		err := r.iterator.Next(&r.row)
		if err != nil {
			return []string{}
		}
	}
	schema := r.iterator.Schema
	r.columns = make([]string, len(schema))
	for i, field := range schema {
		r.columns[i] = field.Name
	}
	return r.columns
}

//Close clears data
func (r *BQRows) Close() error {
	r.iterator = nil
	r.row = nil
	r.rowIndex = 0
	r.columns = nil
	return nil
}

//Next loads the next row into dest
func (r *BQRows) Next(dest []driver.Value) error {
	if r.row == nil || r.rowIndex > 0 {
		err := r.iterator.Next(&r.row)
		if err != nil {
			if err == iterator.Done {
				return io.EOF
			}
			return err
		}
	}
	r.rowIndex++

	if dest == nil {
		dest = make([]driver.Value, len(r.row))
	}
	convertToValue(dest, r.row)
	return nil
}

func convertToValue(dest []driver.Value, row []bigquery.Value) {
	for i, column := range row {
		if bqArr, ok := column.([]bigquery.Value); ok {
			dest[i] = bqArr
			continue
		}
		dest[i] = column
	}
}
