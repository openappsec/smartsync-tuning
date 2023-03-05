package kafka

const (
	kafkaDefaultNetworkProtocol    = "tcp"
	kafkaDefaultDialTimeout        = "15s"
	kafkaDefaultMinBytesPerRequest = 1e3
	kafkaDefaultMaxBytesPerRequest = 10e6
	kafkaDefaultMaxAttempts        = 30
	kafkaOpName                    = "golang-kafka"
	k8sNamespaceEnvKey             = "K8S_NAMESPACE"
)
