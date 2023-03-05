package kafka

import (
	"context"
	"time"

	kafkago "github.com/segmentio/kafka-go"
)

// HandleFunc represents the handler functions
type HandleFunc func(ctx context.Context, body []byte, headers map[string][]byte) error

// RetryPolicy represents the retry policy for kafka consumer
type RetryPolicy struct {
	MaxAttempts     int           // default - 3 attempts, maximum - 5 attempts
	BackoffDelayMin time.Duration // default - 3 seconds, maximum - 1 minute
	BackoffDelayMax time.Duration // default - 3 seconds, maximum - 1 minute
	DLQTopic        string

	CurrentAttempt int    // This shouldn't modified!
	OriginalTopic  string // This shouldn't modified!
}

//ConsumerConfig are the config params for a consumer initialization
type ConsumerConfig struct {
	Brokers                string
	Topic                  string
	GroupID                string
	Partition              int
	Timeout                time.Duration
	MinBytes               int
	MaxBytes               int
	TLS                    bool
	CommitAfterHandlingMsg bool
	RetryPolicy            *RetryPolicy
	// true if running in one of the following namespaces:
	// dev-latest, master-latest, gem-master-latest, gem-pre-prod, pre-prod, staging, prod
	RetryEnabled      bool
	DriverLogsEnabled bool
}

//ProducerConfig are the config params for a consumer initialization
type ProducerConfig struct {
	Brokers           string
	Topic             string
	Timeout           time.Duration
	MaxAttempts       int
	TLS               bool
	DriverLogsEnabled bool
}

// Header is the same as kafka.Header with string values, used for printing
type Header struct {
	Key   string
	Value string
}

// Message is the same as kafka.Message with string values, used for printing
type Message struct {
	Topic string

	// Partition is reads only and MUST NOT be set when writing messages
	Partition int
	Offset    int64
	Key       string
	Value     string
	Headers   []Header

	// If not set at the creation, Time will be automatically set when
	// writing the message.
	Time time.Time
}

// FromKafkaMessage gets a kafka.Message and returns a copy of the message with string values for printing
func FromKafkaMessage(msg kafkago.Message) Message {
	m := Message{
		Topic:     msg.Topic,
		Partition: msg.Partition,
		Offset:    msg.Offset,
		Key:       string(msg.Key),
		Value:     string(msg.Value),
		Time:      msg.Time,
	}

	for _, h := range msg.Headers {
		m.Headers = append(m.Headers, Header{Key: h.Key, Value: string(h.Value)})
	}

	return m
}
