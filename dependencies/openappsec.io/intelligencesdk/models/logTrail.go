package models

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"openappsec.io/errors"
	"openappsec.io/log"
)

// PossibleOutcome is a string representing a possible outcome of a certain action (always equal to the keys of the possibleOutcome map in a LogNode)
type PossibleOutcome string

// PossibleOutcome values
const (
	// Root keys in the LogTree - should be called from the handlers or from the app
	QueryV2Flow                       PossibleOutcome = "queryV2"
	BulkQueriesFlow                   PossibleOutcome = "bulkQuery"
	InvalidationFlow                  PossibleOutcome = "invalidation"
	InvalidationRegistrationFlow      PossibleOutcome = "invalidationRegistration"
	TenantEventFlow                   PossibleOutcome = "tenantEvent"
	AgentConfigurationFlow            PossibleOutcome = "agentConfiguration"
	AsyncGetQueriesAndInvalFlow       PossibleOutcome = "asyncGetQueriesAndInvalidation"
	AsyncPostQueriesFlow              PossibleOutcome = "asyncPostQueries"
	AsyncInvalidationFlow             PossibleOutcome = "asyncInvalidation"
	ValidateTenantsFlow               PossibleOutcome = "validateTenants"
	ExternalSrcRegistrationFlow       PossibleOutcome = "externalSourceRegistration"
	GetAssetFlow                      PossibleOutcome = "getAsset"
	PutAssetFlow                      PossibleOutcome = "putAsset"
	PatchAssetFlow                    PossibleOutcome = "patchAsset"
	DeleteAssetFlow                   PossibleOutcome = "deleteAsset"
	QueryLegacyFlow                   PossibleOutcome = "queryLegacy"
	PostAssetsFlow                    PossibleOutcome = "postAssets"
	QueryV1Flow                       PossibleOutcome = "queryV1"
	ValidateAssetsFlow                PossibleOutcome = "validateAssets"
	ValidateQueriesFlow               PossibleOutcome = "validateQueries"
	AsyncChildRegistrationFlow        PossibleOutcome = "asyncChildRegistration"
	AsyncChildQueriesAndInvalFlow     PossibleOutcome = "asyncChildQueriesAndInvalidation"
	AgentOrchestratorRegistrationFlow PossibleOutcome = "agentOrchestratorRegistration"

	// Query flow possible outcomes
	QueryResultInCache                       PossibleOutcome = "queryResultInCache"
	NoQueryResultInCache                     PossibleOutcome = "noQueryResultInCache"
	NoMatchingExternalSources                PossibleOutcome = "noMatchingExternalSources"
	FoundMatchingExternalSources             PossibleOutcome = "foundMatchingExternalSources"
	FoundAssetsDB                            PossibleOutcome = "foundAssetsDB"
	NotFoundAssetsDB                         PossibleOutcome = "notFoundAssetsDB"
	Done                                     PossibleOutcome = "done"
	InProgress                               PossibleOutcome = "inProgress"
	AgentIntelligenceInProgress              PossibleOutcome = "agentIntelligenceInProgress"
	AgentIntelligenceDone                    PossibleOutcome = "agentIntelligenceDone"
	AgentIntelligenceNotEnoughResultsForPage PossibleOutcome = "agentIntelligenceNotEnoughResultsForPage"
	AgentIntelligenceFoundMoreSourceToQuery  PossibleOutcome = "agentIntelligenceFoundMoreSourcesToQuery"
	AllRecordsExist                          PossibleOutcome = "allRecordsExist"
	AllSourcesDoneSecurityQuery              PossibleOutcome = "allSourcesAreDoneForSecurityQuery"
	AllSourcesDonePagingQuery                PossibleOutcome = "allSourcesAreDoneForPagingQuery"
	FoundExternalSourcesToQuery              PossibleOutcome = "foundExternalSourcesToQuery"
	NotAllRecordsExist                       PossibleOutcome = "notAllRecordsExist"
	QueryIntelligenceSource                  PossibleOutcome = "queryIntelligenceSource"
	StatusRecordsAlreadyExist                PossibleOutcome = "statusRecordsAlreadyExist"
	NoResultFromSyncSources                  PossibleOutcome = "noResultFromSyncSources"
	ResultFromSyncSource                     PossibleOutcome = "resultFromSyncSource"
	ResultFromSyncSourceAgent                PossibleOutcome = "resultFromSyncSourceAgent"
	NotAllSourcesAreDone                     PossibleOutcome = "notAllSourcesAreDone"
	ReachedTimeLimitSecurityQuery            PossibleOutcome = "reachedTimeLimitSecurityQuery"
	ReachedTimeLimitPagingQuery              PossibleOutcome = "reachedTimeLimitPagingQuery"
	NotReachedTimeLimit                      PossibleOutcome = "notReachedTimeLimit"
	AgentIntelligenceAsAux                   PossibleOutcome = "agentIntelligenceAsAux"

	// Async Invalidation flow possible outcomes
	FoundMatchingAssets                  PossibleOutcome = "foundMatchingAssets"
	NotFoundMatchingAssets               PossibleOutcome = "notFoundMatchingAssets"
	SuccessfulDeleteTriggersInvalidation PossibleOutcome = "successfulDeleteTriggersInvalidation"
)

const (
	// LogTrailSeparator string separator used when representing the logTrail as a string
	LogTrailSeparator = " | "
	ohNoErrMsgPrefix  = "Oh no! - this shouldn't have happen: Failed to log info: %s"
)

// LogNode is a node within the LogTree
type LogNode struct {
	NodeName         string                      `json:"nodeName"`
	ActionName       string                      `json:"actionName"`
	PossibleOutcomes map[PossibleOutcome]LogNode `json:"possibleOutcomes"`
}

// LogTree is a tree representation of all log possible flows
type LogTree map[PossibleOutcome]LogNode

// LogTrail is a path in the LogTree representing the current flow.
type LogTrail struct {
	VisitedNodesNames []string          `json:"visitedNodesNames"`
	VisitedNodesKeys  []PossibleOutcome `json:"visitedNodesKeys"`
	Stopper           time.Time         `json:"stopper"`
	TimeInterval      []string          `json:"timeInterval"`
	LogTree           LogTree           `json:"logTree"`
}

// LogInfo logs an info message to log in the following format: "Step <stepNum> | <action> | <result> "
// Wheres:
// 1. <stepNum> is calculated based on the length of the path in the logTree up until this point.
// 2. <action> is the action of the current node
// 3. <result> is the name of the nextNode which is identified by the provided argument outcome
func (lt *LogTrail) LogInfo(ctx context.Context, eventID string, fields log.Fields, outcome PossibleOutcome) {
	// Step 1: Get the current node based on the visitedNodesKeys
	currNode, err := lt.getCurrentNode()
	if err != nil {
		log.WithContextAndEventID(ctx, "5df294ce-a047-40ab-ad30-4c5d672892d6").Errorf(ohNoErrMsgPrefix, err.Error())
		return
	}

	// Step 2: Get the next node based on the provided outcome
	// (there can not be an action without an outcome --> there should always be a next node)
	nextNode, ok := currNode.PossibleOutcomes[outcome]
	if !ok {
		errMsgPartTwo := fmt.Sprintf("Failed to find the outcome (%s) in the currentNodes possible outcomes: %+v", outcome, reflect.ValueOf(currNode.PossibleOutcomes).MapKeys())
		lt.LogErrorf(ctx, "4174f91f-cbd6-4684-9088-402b28f0ade9", log.Fields{}, ohNoErrMsgPrefix, errMsgPartTwo)
		return
	}

	// Step 3: Build the info message
	msg := lt.buildInfoMessage(currNode, nextNode)

	// Step 4: Indicate a move to the next node (IMPORTANT - should be done only after you have the message at hand)
	lt.VisitedNodesKeys = append(lt.VisitedNodesKeys, outcome)
	lt.VisitedNodesNames = append(lt.VisitedNodesNames, nextNode.NodeName)
	lt.TimeInterval = append(lt.TimeInterval, fmt.Sprintf("%d", time.Since(lt.Stopper).Milliseconds()))
	lt.Stopper = time.Now()

	// Step 5: Get the updated log fields (with the indication of the current flow after updating the logTrail) + log it!
	log.WithContextAndEventID(ctx, eventID).WithFields(lt.AddLogTrailToLogFields(fields)).Info(msg)
}

// LogDebug logs debugs + adds the log trail as a log field
func (lt *LogTrail) LogDebug(ctx context.Context, eventID string, fields log.Fields, msg string) {
	log.WithContextAndEventID(ctx, eventID).WithFields(lt.AddLogTrailToLogFields(fields)).Debug(msg)

}

// LogDebugf logs debugs with parameters + adds the log trail as a log field
func (lt *LogTrail) LogDebugf(ctx context.Context, eventID string, fields log.Fields, msg string, args ...interface{}) {
	log.WithContextAndEventID(ctx, eventID).WithFields(lt.AddLogTrailToLogFields(fields)).Debugf(msg, args...)
}

// LogWarn logs warnings + adds the log trail as a log field
func (lt *LogTrail) LogWarn(ctx context.Context, eventID string, fields log.Fields, msg string) {
	log.WithContextAndEventID(ctx, eventID).WithFields(lt.AddLogTrailToLogFields(fields)).Warn(msg)
}

// LogWarnf logs warnings with parameters + adds the log trail as a log field
func (lt *LogTrail) LogWarnf(ctx context.Context, eventID string, fields log.Fields, msg string, args ...interface{}) {
	log.WithContextAndEventID(ctx, eventID).WithFields(lt.AddLogTrailToLogFields(fields)).Warnf(msg, args...)
}

// LogError logs errors + adds the log trail as a log field
func (lt *LogTrail) LogError(ctx context.Context, eventID string, fields log.Fields, msg string) {
	log.WithContextAndEventID(ctx, eventID).WithFields(lt.AddLogTrailToLogFields(fields)).Error(msg)
}

// LogErrorf logs errors with parameters + adds the log trail as a log field
func (lt *LogTrail) LogErrorf(ctx context.Context, eventID string, fields log.Fields, msg string, args ...interface{}) {
	log.WithContextAndEventID(ctx, eventID).WithFields(lt.AddLogTrailToLogFields(fields)).Errorf(msg, args...)
}

func (lt *LogTrail) getCurrentNode() (LogNode, error) {
	var currNode LogNode
	var ok bool
	for i, nodeKey := range lt.VisitedNodesKeys {
		nodeKey := nodeKey
		if i == 0 {
			currNode, ok = lt.LogTree[nodeKey]
			if !ok {
				return LogNode{}, errors.Errorf("Failed to find log node %s in logTree", nodeKey)
			}
		} else {
			currNode, ok = currNode.PossibleOutcomes[nodeKey]
			if !ok {
				return LogNode{}, errors.Errorf("Failed to find log node %s in logTree", nodeKey)
			}
		}
	}

	return currNode, nil
}

func (lt *LogTrail) buildInfoMessage(currNode, nextNode LogNode) string {
	stepNum := len(lt.VisitedNodesNames)
	action := currNode.ActionName
	outcomeName := nextNode.NodeName
	return fmt.Sprintf("Step %d%sAction: %s%sOutcome: %s", stepNum, LogTrailSeparator, action, LogTrailSeparator, outcomeName)
}

// AddLogTrailToLogFields adds a field to log fields with the log trail (all visited node name until this point)
func (lt *LogTrail) AddLogTrailToLogFields(fields log.Fields) log.Fields {
	fields[LogFieldLogTrail] = strings.Join(lt.VisitedNodesNames, LogTrailSeparator)
	fields[LogFieldLogTrailTimeInterval] = strings.Join(lt.TimeInterval, LogTrailSeparator)
	return fields
}

// Fork returns a copy of LogTrail without impacting the current LogTrail
func (lt *LogTrail) Fork() *LogTrail {
	ltCopy := *lt
	ltCopy.VisitedNodesNames = make([]string, len(lt.VisitedNodesNames))
	copy(ltCopy.VisitedNodesNames, lt.VisitedNodesNames)

	ltCopy.VisitedNodesKeys = make([]PossibleOutcome, len(lt.VisitedNodesKeys))
	copy(ltCopy.VisitedNodesKeys, lt.VisitedNodesKeys)

	ltCopy.TimeInterval = make([]string, len(lt.TimeInterval))
	copy(ltCopy.TimeInterval, lt.TimeInterval)

	return &ltCopy
}

// ForkAndChangeFlow returns a copy of LogTrail with visited log keys are set to a beginning of a different flow.
// If withPastVisitedNodeNames == true: The copy of LogTrail would include all past visited node names.
// Else (withPastVisitedNodeNames == false): The past visited nodes would include only the node name of the flowName
// Provided flowName must be a root level possible outcome, otherwise it would return an error
func (lt *LogTrail) ForkAndChangeFlow(flowName PossibleOutcome, withPastVisitedNodeNames bool) (*LogTrail, error) {
	initialNode, ok := lt.LogTree[flowName]
	if !ok {
		return lt, errors.Errorf("Failed to fork and change flow - provided flowName %s isn't a possible outcome from root", flowName)
	}

	ltCopy := *lt
	ltCopy.VisitedNodesKeys = []PossibleOutcome{flowName}
	if withPastVisitedNodeNames {
		ltCopy.VisitedNodesNames = make([]string, len(lt.VisitedNodesNames))
		copy(ltCopy.VisitedNodesNames, lt.VisitedNodesNames)
		ltCopy.TimeInterval = make([]string, len(lt.TimeInterval))
		copy(ltCopy.TimeInterval, lt.TimeInterval)
	} else {
		ltCopy.VisitedNodesNames = []string{initialNode.NodeName}
	}

	return &ltCopy, nil
}

// SetOutput changes the output of the logs printed (used in tests...)
func (lt *LogTrail) SetOutput(w io.Writer) {
	log.SetOutput(w)
}
