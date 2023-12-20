package bqadapter

import (
	"database/sql/driver"
	"fmt"
	"strings"

	"cloud.google.com/go/bigquery"
	"openappsec.io/smartsync-tuning/models"
	"openappsec.io/errors"
	"google.golang.org/api/googleapi"
)

// Field names
const (
	fieldNameLogID         = "logindex"
	fieldNameCountHigh     = "high_severity"
	fieldNameCountCritical = "critical_severity"
	fieldNameSeverity      = "eventseverity"
	fieldNameIncidentTypes = "waapincidenttype"
	fieldNameSource        = "httpsourceid"
	fieldNameURL           = "httpuripath"
	fieldNameParamName     = "matchedparameter"
	fieldNameParamValue    = "matchedsample"
	fieldNameAssetName     = "assetname"
	fieldNameLocation      = "matchedlocation"

	confKeyWaapFullDatasetID = "DATATUBE_WAAP_DATASET_ID"
	confKeyElpisLogsTenant   = "ELPIS_LOGS_TENANT"

	maxTableSuffix = 3
)

// GenBQQueries generate bigquery queries
type GenBQQueries struct {
	dataset     string
	elpisTenant string
}

// Insert not implemented for bigquery
func (gen *GenBQQueries) Insert(_ *models.AgentMessage) (string, []driver.Value, error) {
	return "", []driver.Value{}, driver.ErrSkip
}

// CreateTable not implemented for bigquery
func (gen *GenBQQueries) CreateTable(_ string) (string, error) {
	return "", driver.ErrSkip
}

// CreateDatabase not implemented for bigquery
func (gen *GenBQQueries) CreateDatabase() string {
	return ""
}

// CreateTablePartition not implemented for bigquery
func (gen *GenBQQueries) CreateTablePartition(_ string, _ string) (string, error) {
	return "", driver.ErrSkip
}

// ParseError return the appropriate class for driver specific error
func (gen *GenBQQueries) ParseError(err error) errors.Class {
	gErr, ok := err.(*googleapi.Error)
	if !ok {
		return errors.ClassUnknown
	}
	if gErr.Code == 404 {
		return errors.ClassNotFound
	}
	if gErr.Code == 400 && strings.Contains(gErr.Body, "jobRateLimitExceeded") {
		return errors.ClassForbidden
	}
	return errors.ClassUnknown
}

// NewQueriesGenerator creates a new bigquery queries gen
func NewQueriesGenerator(config Configuration) (*GenBQQueries, error) {
	bqq := &GenBQQueries{}
	err := bqq.init(config)
	if err != nil {
		return &GenBQQueries{}, err
	}
	return bqq, nil
}

func (gen *GenBQQueries) init(config Configuration) error {
	dataset, err := config.GetString(confKeyWaapFullDatasetID)
	if err != nil {
		return errors.Wrapf(err, "get %v returned an error", confKeyWaapFullDatasetID)
	}
	gen.dataset = dataset

	elpisTenant, err := config.GetString(confKeyElpisLogsTenant)
	if err != nil {
		return errors.Wrapf(err, "failed to get elpis logs tenant")
	}
	gen.elpisTenant = strings.Replace(elpisTenant, "-", "_", -1)

	return nil
}

// GetExceptionsQuery query for exceptions
func (gen *GenBQQueries) GetExceptionsQuery(tenantID string) string {
	table, extendWhere := gen.handleTenant(tenantID)
	return fmt.Sprintf(
		`SELECT
			tenant_id,
			exceptionId,
			assetid,
			MAX(eventtime) AS lastHitEvent,
			COUNT(exceptionId) AS hitCountPerAsset,
			SUM(COUNT(exceptionId))
				OVER (
					PARTITION BY tenant_id, exceptionId
					ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
				) AS hitCountPerException
		FROM`+"`"+table+"`"+`,
			UNNEST(exceptionIdList) exceptionId
		WHERE
			time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 14 DAY)
			AND exceptionId IS NOT NULL %v
		GROUP BY tenant_id, exceptionId, assetid
		ORDER BY tenant_id, exceptionId`, extendWhere)
}

// GetUrlsForCollapsingFormat get urls for tokenizer
func (gen *GenBQQueries) GetUrlsForCollapsingFormat(tenantID string) string {
	table, extendWhere := gen.handleTenant(tenantID)
	return fmt.Sprintf("SELECT tenant_id, assetid, ARRAY_AGG(DISTINCT httpuripath) as %v"+
		" FROM `%v` WHERE eventname='Web Request' AND (practicesubtype='Web Application' or practicesubtype='Web API') AND time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)"+
		" AND ((matchedparameter is null AND matchedlocation='body') OR matchedlocation='url')"+
		" AND httpuripath is not null "+extendWhere+
		" GROUP BY tenant_id, assetid", models.FieldNameURIs, table)
}

// GetParamsForCollapsingFormat get params for tokenizer
func (gen *GenBQQueries) GetParamsForCollapsingFormat(tenantID string) string {
	table, extendWhere := gen.handleTenant(tenantID)
	return fmt.Sprintf("SELECT tenant_id, assetid, ARRAY_AGG(DISTINCT matchedparameter) as %v"+
		" FROM `%v` WHERE eventname='Web Request' AND (practicesubtype='Web Application' or practicesubtype='Web API') AND time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)"+
		" AND matchedparameter is not null AND matchedlocation='body' "+extendWhere+
		" GROUP BY tenant_id, assetid", models.FieldNameParams, table)
}

// GetTuneParameterQuery gen query for tuning events
func (gen *GenBQQueries) GetTuneParameterQuery(parameter string, minCount int, tenantID string) string {
	table, extendWhere := gen.handleTenant(tenantID)

	renameMap := map[string]string{
		fieldNameURL:        models.EventTypeURL,
		fieldNameSource:     models.EventTypeSource,
		fieldNameParamName:  models.EventTypeParamName,
		fieldNameParamValue: models.EventTypeParamVal,
	}
	var havingClause string
	switch parameter {
	case fieldNameURL:
		havingClause = fmt.Sprintf("HAVING %v>=%v", models.FieldNameCountParameters, minCount)
	case fieldNameSource:
		havingClause = fmt.Sprintf("HAVING %v>=%v", models.FieldNameCountURLs, minCount)
	case fieldNameParamName:
		havingClause = fmt.Sprintf("HAVING %v>=%v", models.FieldNameCountSources, minCount)
	case fieldNameParamValue:
		havingClause = fmt.Sprintf(
			"HAVING (%v>=%v or %v>=%v) and %v>=%v",
			models.FieldNameCountURLs, minCount,
			models.FieldNameCountParameters, minCount,
			models.FieldNameCountSources, minCount,
		)
	}

	whereClause := "time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 120 DAY) " +
		"and time > TIMESTAMP_SUB(t, INTERVAL 7 DAY) " +
		"and " + fieldNameLogID + " IS NOT NULL " +
		"and eventname='Web Request' and (practicesubtype='Web Application' or practicesubtype='Web API') and (" + fieldNameSeverity +
		"='Critical' or " + fieldNameSeverity + "='High') "
	if parameter == fieldNameParamName {
		whereClause += "and " + fieldNameParamName + "!='' "
	}

	selectClause := "SELECT A." + models.FieldNameTenantID + ",A." + models.FieldNameAssetID + "," +
		"ANY_VALUE(" + fieldNameAssetName + ") as " + models.FieldNameAssetName + "," +
		parameter + " as " + renameMap[parameter] + "," +
		count(fieldNameSource, models.FieldNameCountSources) + "," +
		fieldNameSeverity + " as " + models.FieldNameSeverity + "," +
		"ARRAY_AGG(distinct IFNULL(" + fieldNameIncidentTypes + ", 'General')) as " + models.FieldNameAttackTypes + "," +
		count(fieldNameURL, models.FieldNameCountURLs) + "," +
		count(fieldNameParamName, models.FieldNameCountParameters) + "," +
		count("*", models.FieldNameCountAll) + "," +
		"ARRAY_AGG(distinct " + fieldNameLogID + " LIMIT 10000) as " + models.FieldNameLogIDs

	fromClause := "`" + table + "` AS A" +
		" INNER JOIN (SELECT" +
		"   tenant_id," +
		"   assetid," +
		"   MAX(time) AS t" +
		" FROM" +
		" `" + table + "`" +
		" WHERE" +
		"   time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 120 DAY)" +
		"   AND eventname='Web Request'" +
		"   AND (practicesubtype='Web Application' or practicesubtype='Web API') " + extendWhere +
		" GROUP BY" +
		"   tenant_id," +
		"   assetid) AS B " +
		" ON " +
		" A.tenant_id = B.tenant_id" +
		" AND A.assetid = B.assetid"

	return fmt.Sprintf(
		selectClause+
			" FROM %[2]v WHERE "+whereClause+
			"GROUP BY "+models.FieldNameTenantID+","+models.FieldNameAssetID+","+
			fieldNameSeverity+",%[1]v %[3]v",
		parameter, fromClause, havingClause,
	)
}

// GetTuneURLQueryFormat generate query for url tuning event
func (gen *GenBQQueries) GetTuneURLQueryFormat(minCount int, tenantID string) string {
	havingClause := fmt.Sprintf("HAVING %v>=%v and %v=0",
		models.FieldNameCountSources, minCount, models.FieldNameCountParameters)

	whereClause := "time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 120 DAY) " +
		"and time > TIMESTAMP_SUB(t, INTERVAL 7 DAY) " +
		"and eventname='Web Request' and (practicesubtype='Web Application' or practicesubtype='Web API') and (" + fieldNameSeverity + "='Critical' or " + fieldNameSeverity + "='High') " +
		"and " + fieldNameLocation + "='body' "

	selectClause := "SELECT A." + models.FieldNameTenantID + ",A." + models.FieldNameAssetID + "," +
		"ANY_VALUE(" + fieldNameAssetName + ") as " + models.FieldNameAssetName + "," +
		fieldNameURL + " as " + models.EventTypeURL + "," +
		count(fieldNameSource, models.FieldNameCountSources) + "," +
		fieldNameSeverity + " as " + models.FieldNameSeverity + "," +
		"ARRAY_AGG(distinct IFNULL(" + fieldNameIncidentTypes + ", 'General')) as " + models.FieldNameAttackTypes + "," +
		count(fieldNameURL, models.FieldNameCountURLs) + "," +
		count(fieldNameParamName, models.FieldNameCountParameters) + "," +
		count("*", models.FieldNameCountAll) + "," +
		"ARRAY_AGG(distinct " + fieldNameLogID + " LIMIT 10000) as " + models.FieldNameLogIDs

	table, extendWhere := gen.handleTenant(tenantID)

	fromClause := "`" + table + "` AS A" +
		" INNER JOIN (SELECT" +
		"   tenant_id," +
		"   assetid," +
		"   MAX(time) AS t" +
		" FROM" +
		" `" + table + "`" +
		" WHERE" +
		"   time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 120 DAY)" +
		"   AND eventname='Web Request'" +
		"   AND (practicesubtype='Web Application' or practicesubtype='Web API')" +
		extendWhere +
		" GROUP BY" +
		"   tenant_id," +
		"   assetid) AS B " +
		" ON" +
		" A.tenant_id = B.tenant_id" +
		" AND A.assetid = B.assetid"

	return fmt.Sprintf(
		selectClause+
			" FROM %[2]v WHERE "+whereClause+
			"GROUP BY "+models.FieldNameTenantID+","+models.FieldNameAssetID+","+
			fieldNameSeverity+",%[1]v %[3]v",
		fieldNameURL, fromClause, havingClause,
	)
}

func count(fieldName, modelFieldName string) string {
	count := "distinct " + fieldName
	if fieldName == "*" {
		count = fieldName
	}
	return fmt.Sprintf("count(%v) as %v", count, modelFieldName)
}

func (gen *GenBQQueries) handleTenant(tenantID string) (string, string) {
	if tenantID == "All" {
		table := fmt.Sprintf("%s.*", gen.dataset)
		return table, ""
	}
	if strings.HasPrefix(strings.ToLower(tenantID), elpisPrefix) {
		table := fmt.Sprintf("%s.%s%s", gen.dataset, tablePrefix, gen.elpisTenant)
		where := fmt.Sprintf("and %s='%s' ", models.FieldNameTenantID, tenantID)
		return table, where
	}
	if len(tenantID) < maxTableSuffix {
		table := fmt.Sprintf("%s.*", gen.dataset)
		where := fmt.Sprintf("and ENDS_WITH(_TABLE_SUFFIX,'%v') ", tenantID)
		return table, where
	}
	tableSuffix := strings.Replace(tenantID, "-", "_", -1)
	table := fmt.Sprintf("%s.%s%s", gen.dataset, tablePrefix, tableSuffix)
	return table, ""
}

// GetTotalRequests query for total requests
func (gen *GenBQQueries) GetTotalRequests(tenantID string) string {
	table, extendWhere := gen.handleTenant(tenantID)

	internalQSelect := "SELECT eventtime, tenant_id, assetid, agentid, logindex, ANY_VALUE(reservedngena) as reservedngena"
	internalQFrom := fmt.Sprintf("FROM `%v`", table)
	internalQWhere := "WHERE LOWER(eventname)='waap telemetry' and time <= CURRENT_TIMESTAMP() " +
		"and reservedngena is not null " + extendWhere
	internalQGroupBy := "GROUP BY eventtime, tenant_id, assetid, tenant_id, agentid, logindex"
	internalQuery := fmt.Sprintf("%v %v %v %v", internalQSelect, internalQFrom, internalQWhere, internalQGroupBy)
	queryStr := fmt.Sprintf("select tenant_id, assetid, sum(reservedngena) as %v FROM (%v) GROUP BY tenant_id, assetid",
		models.FieldNameCountAll, internalQuery)

	return queryStr
}

// GetNumOfRequests query for total requests
func (gen *GenBQQueries) GetNumOfRequests(tenantID string) string {
	table, extendWhere := gen.handleTenant(tenantID)

	internalQSelect := "SELECT eventtime, assetid, agentid, logindex, ANY_VALUE(reservedngena) as reservedngena"
	internalQFrom := fmt.Sprintf("FROM `%v`", table)
	internalQWhere := "WHERE LOWER(eventname)='waap telemetry' and DATE(time) >= " +
		"'2021-01-01' " + extendWhere
	internalQGroupBy := "GROUP BY eventtime, assetid, agentid, logindex"
	internalQuery := fmt.Sprintf("%v %v %v %v", internalQSelect, internalQFrom, internalQWhere, internalQGroupBy)
	return fmt.Sprintf("select sum(reservedngena) as %v FROM (%v)", models.FieldNameCountAll, internalQuery)
}

// GetElapsedTime generates a query to get general data of an assetID
func (gen *GenBQQueries) GetElapsedTime(tenantID string) string {
	table, extendWhere := gen.handleTenant(tenantID)

	queryStr := fmt.Sprintf("select tenant_id, assetid, UNIX_SECONDS(min(time)) as %v FROM `%v` WHERE "+
		"LOWER(eventname)='waap telemetry' and time <= CURRENT_TIMESTAMP() and reservedngena>0 "+extendWhere+
		" GROUP BY tenant_id, assetid", models.FieldNameStartTime, table)

	return queryStr
}

// GetSeverityStatsQuery generates a query to get specific data with respect to severity
func (gen *GenBQQueries) GetSeverityStatsQuery(tenantID string) string {
	table, extendWhere := gen.handleTenant(tenantID)

	str := `SELECT
  ` + models.FieldNameTenantID + `,
  ` + models.FieldNameAssetID + `,
  SUM(requests) AS ` + models.FieldNameCountAll + `,
  SUM(high_severity) AS ` + fieldNameCountHigh + `,
  SUM(critical_severity) AS ` + fieldNameCountCritical + `
FROM (
  SELECT
    eventtime,
    tenant_id,
    assetid,
    agentid,
    logindex,
    IFNULL(ANY_VALUE(reservedngena), 0) AS requests,
    IFNULL(ANY_VALUE(reservedngeni), 0) AS high_severity,
    IFNULL(ANY_VALUE(reservedngenj), 0) AS critical_severity
  FROM
    ` + "`" + table + "`" + `
  WHERE
    LOWER(eventname)='waap telemetry'
    AND time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
    AND reservedngena IS NOT NULL ` + extendWhere + `
  GROUP BY
    eventtime,
    tenant_id,
    assetid,
    tenant_id,
    agentid,
    logindex)
GROUP BY
  tenant_id,
  assetid`
	return str
}

// GetGeneralStatsQuery generates a query to get general data of an assetID
func (gen *GenBQQueries) GetGeneralStatsQuery(tenantID string) string {
	table, extendWhere := gen.handleTenant(tenantID)
	return fmt.Sprintf(
		"SELECT "+models.FieldNameTenantID+","+models.FieldNameAssetID+",count(distinct "+fieldNameSource+") as number_of_sources,"+
			"count(distinct "+fieldNameURL+") as number_of_urls,count(*) as number_of_requests,"+
			"TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), min(time), HOUR) as "+models.FieldNameElapsedTime+" FROM `%v` "+
			"WHERE time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY) "+extendWhere+
			"and eventname='Web Request' and (practicesubtype='Web Application' or practicesubtype='Web API')"+
			"GROUP BY "+models.FieldNameTenantID+","+models.FieldNameAssetID, table,
	)
}

// GenerateLogQuery created a log query for smartview
func (gen *GenBQQueries) GenerateLogQuery(data models.TuneEvent, assetName string) string {
	queryFieldsMap := map[string]string{
		models.EventTypeSource:    fieldNameSource,
		models.EventTypeURL:       fieldNameURL,
		models.EventTypeParamName: fieldNameParamName,
		models.EventTypeParamVal:  fieldNameParamValue,
	}
	query := []string{fmt.Sprintf("%v:%v", fieldNameSeverity, strings.Title(data.Severity))}
	if assetName != "" {
		query = append(query, fmt.Sprintf("%v:\"%v\"", fieldNameAssetName, assetName))
	}
	query = append(query, fmt.Sprintf("%v:\"%v\"", queryFieldsMap[data.EventType], data.EventTitle))
	return strings.Join(query, " and ")
}

// ScanArray scan response value into array arr
func (gen *GenBQQueries) ScanArray(value driver.Value, arr any) error {
	switch arr := arr.(type) {
	case *[]int64:
		return parseIntArr(value, arr)
	case *[]string:
		return parseStrArr(value, arr)
	}
	return errors.Errorf("type %T not supported", arr)
}

func parseStrArr(value driver.Value, arr *[]string) error {
	vals, ok := value.([]bigquery.Value)
	if !ok {
		return errors.Errorf("failed to convert %T to %T", value, vals)
	}
	for _, val := range vals {
		*arr = append(*arr, fmt.Sprint(val))
	}
	return nil
}

func parseIntArr(value driver.Value, arr *[]int64) error {
	vals, ok := value.([]bigquery.Value)
	if !ok {
		return errors.Errorf("failed to convert %T to %T", value, vals)
	}
	for _, val := range vals {
		*arr = append(*arr, val.(int64))
	}
	return nil
}
