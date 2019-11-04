package nmagentclient

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/Azure/azure-container-networking/log"
)

const (
	// Http connection timeout duration in milliseconds
	connectionTimeoutDurationMs = 5000
	// Response header timeout duration in milliseconds
	responseHeaderTimeoutDurationMs = 120000
)

// Creating http client object to be reused instead of creating one every time.
// This helps make use of the cached tcp connections.
// Clients are safe for concurrent use by multiple goroutines.
var httpClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: time.Duration(connectionTimeoutDurationMs) * time.Millisecond,
		}).DialContext,
		ResponseHeaderTimeout: time.Duration(responseHeaderTimeoutDurationMs) * time.Millisecond,
	},
}

// JoinNetwork joins the given network
func JoinNetwork(
	networkID string,
	joinNetworkURL string) (*http.Response, error) {
	log.Printf("[NMAgentClient] JoinNetwork: %s", networkID)

	// Empty body is required as wireserver cannot handle a post without the body.
	var body bytes.Buffer
	json.NewEncoder(&body).Encode("")
	response, err := httpClient.Post(joinNetworkURL, "application/json", &body)

	if err == nil && response.StatusCode == http.StatusOK {
		defer response.Body.Close()
	}

	log.Printf("[NMAgentClient][Response] Join network: %s. Response: %+v. Error: %v",
		networkID, response, err)

	return response, err
}

// PublishNetworkContainer publishes given network container
func PublishNetworkContainer(
	networkContainerID string,
	createNetworkContainerURL string,
	requestBodyData []byte) (*http.Response, error) {
	log.Printf("[NMAgentClient] PublishNetworkContainer NC: %s", networkContainerID)

	requestBody := bytes.NewBuffer(requestBodyData)
	response, err := httpClient.Post(createNetworkContainerURL, "application/json", requestBody)

	log.Printf("[NMAgentClient][Response] Publish NC: %s. Response: %+v. Error: %v",
		networkContainerID, response, err)

	return response, err
}

// UnpublishNetworkContainer unpublishes given network container
func UnpublishNetworkContainer(
	networkContainerID string,
	deleteNetworkContainerURL string) (*http.Response, error) {
	log.Printf("[NMAgentClient] UnpublishNetworkContainer NC: %s", networkContainerID)

	// Empty body is required as wireserver cannot handle a post without the body.
	var body bytes.Buffer
	json.NewEncoder(&body).Encode("")
	response, err := httpClient.Post(deleteNetworkContainerURL, "application/json", &body)

	log.Printf("[NMAgentClient][Response] Unpublish NC: %s. Response: %+v. Error: %v",
		networkContainerID, response, err)

	return response, err
}
