package dncclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/logger"
	acn "github.com/Azure/azure-container-networking/common"
)

const (
	// RegisterNodeURLFmt: /networks/{infraNetworkID}/node/{nodeID}
	registerNodeURLFmt = "%s/networks/%s/node/%s%s"
	// SyncNodeNetworkContainersURLFmt: /networks/{infraNetworkID}/node/{nodeID}/networkcontainers
	syncNodeNetworkContainersURLFmt = "%s/networks/%s/node/%s/networkcontainers%s"

	dncApiVersion = "?api-version=2018-03-01"
)

// NodeRegistrationRequest - Struct to hold node registration request.
type NodeRegistrationRequest struct {
	NumCores int `json:"NumCores"`
}

// RegisterNode registers the node with managed DNC
func RegisterNode(httpRestService cns.HTTPService, dncEP, infraVnet, nodeID string) {
	logger.Printf("[dncclient] Registering node: %s with Infrastructure Network: %s dncEP: %s", nodeID, infraVnet, dncEP)

	var (
		registerNodeURL = fmt.Sprintf(registerNodeURLFmt, dncEP, infraVnet, nodeID, dncApiVersion)
		response        *http.Response
		err             = fmt.Errorf("")
		body            bytes.Buffer
		httpc           = acn.GetHttpClient()
	)

	nodeRegistrationRequest := NodeRegistrationRequest{
		NumCores: runtime.NumCPU(),
	}
	json.NewEncoder(&body).Encode(nodeRegistrationRequest)

	for sleep := true; err != nil; sleep = true {
		response, err = httpc.Post(registerNodeURL, "application/json", &body)
		if err == nil {
			if response.StatusCode == http.StatusOK {
				var req cns.SetOrchestratorTypeRequest
				json.NewDecoder(response.Body).Decode(&req)
				httpRestService.SetNodeOrchestrator(&req)
				sleep = false
			} else {
				err = fmt.Errorf("[dncclient] Failed to register node with http status code %s", strconv.Itoa(response.StatusCode))
				logger.Errorf(err.Error())
			}

			response.Body.Close()
		} else {
			logger.Errorf("[dncclient] Failed to register node with err: %+v", err)
		}

		if sleep {
			time.Sleep(acn.FiveSeconds)
		}
	}

	logger.Printf("[dncclient] Node: %s Registered", nodeID)
}

// SyncNodeNcStatus retrieves the NCs scheduled on this node by DNC
func SyncNodeNcStatus(dncEP, infraVnet, nodeID string) (cns.NodeInfoResponse, error) {
	var (
		syncNodeNcStatusURL = fmt.Sprintf(syncNodeNetworkContainersURLFmt, dncEP, infraVnet, nodeID, dncApiVersion)
		nodeInfoResponse    cns.NodeInfoResponse
		httpc               = acn.GetHttpClient()
	)

	logger.Printf("[dncclient] SyncNodeNcStatus: Node: %s, InfraVnet: %s", nodeID, infraVnet)

	response, err := httpc.Get(syncNodeNcStatusURL)
	if err == nil {
		if response.StatusCode == http.StatusOK {
			err = json.NewDecoder(response.Body).Decode(&nodeInfoResponse)
		} else {
			err = fmt.Errorf("%d", response.StatusCode)
		}

		response.Body.Close()
	}

	return nodeInfoResponse, err
}
