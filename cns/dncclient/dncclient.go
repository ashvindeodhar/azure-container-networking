package dncclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/configuration"
	"github.com/Azure/azure-container-networking/cns/logger"
	acn "github.com/Azure/azure-container-networking/common"

	"context"

	ad "github.com/Azure/azure-container-networking/cns/dncclient/activedirectory"
)

const (
	// Note: RegisterNodeURLFmt: /networks/{infraNetworkID}/node/{nodeID}
	registerNodeURLFmt = "%s/networks/%s/node/%s%s"
	// Note: SyncNodeNetworkContainersURLFmt: /networks/{infraNetworkID}/node/{nodeID}/networkcontainers
	syncNodeNetworkContainersURLFmt = "%s/networks/%s/node/%s/networkcontainers%s"

	dncAPIVersion             = "?api-version=2018-03-01"
	registerNodeRetryInterval = 5 * time.Second
	// TODO: Reset the resource endpoint to dnc.azure.com once the issue with
	// first party portal encryption is resolved. Using the 3rd party app resource ID as
	// a workaround for now.
	//dncResourceEndpoint       = "https://dnc.azure.com/"
	dncResourceEndpoint = "faabc326-f53f-40a3-b378-4bc9c7ae9130"

	httpReqHeaderKeyAuth   = "Authorization"
	httpReqHeaderKeyAccept = "Accept"
)

// DNCClient struct
type DNCClient struct {
	dncEndpointDns      string
	infraVnet           string
	nodeID              string
	nodeManagedIdentity string
	tokenFetcher        ad.TokenFetcher
	httpClient          *http.Client
}

// NodeRegistrationRequest - Struct to hold node registration request.
type NodeRegistrationRequest struct {
	NumCores int `json:"NumCores"`
}

// NewDNCClient creates a new DNCClient
func NewDNCClient(
	tokenFetcher ad.TokenFetcher,
	cnsConfig *configuration.CNSConfig) *DNCClient {
	httpCl := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: time.Duration(cnsConfig.HttpClientSettings.ConnectionTimeout) * time.Second,
			}).DialContext,
			ResponseHeaderTimeout: time.Duration(cnsConfig.HttpClientSettings.ResponseHeaderTimeout) * time.Second,
		},
	}

	client := &DNCClient{
		dncEndpointDns:      cnsConfig.ManagedSettings.DncEndpointDns,
		infraVnet:           cnsConfig.ManagedSettings.InfrastructureNetworkID,
		nodeID:              cnsConfig.ManagedSettings.NodeID,
		nodeManagedIdentity: cnsConfig.ManagedSettings.NodeManagedIdentity,
		tokenFetcher:        tokenFetcher,
		httpClient:          httpCl,
	}

	return client
}

func GetTokenFetcher(
	nodeManagedIdentity string) (ad.TokenFetcher, error) {
	if nodeManagedIdentity != "" {
		return &ad.AADTokenFetcher{ClientID: nodeManagedIdentity}, nil
	}

	return nil, fmt.Errorf("Empty node managed identity")
}

func (dc *DNCClient) getOAuthToken() (string, error) {
	return dc.tokenFetcher.GetOAuthToken(context.Background(), dncResourceEndpoint)
}

// RegisterNode registers the node with managed DNC
func (dc *DNCClient) RegisterNode() *cns.SetOrchestratorTypeRequest {
	logger.Printf("[dncclient] Registering node: %s with Infrastructure Network: %s dncEP: %s",
		dc.nodeID, dc.infraVnet, dc.dncEndpointDns)

	var (
		registerNodeURL = fmt.Sprintf(registerNodeURLFmt, dc.dncEndpointDns,
			dc.infraVnet, dc.nodeID, dncAPIVersion)
		body bytes.Buffer
	)

	// Create a body with number of CPU cores
	nodeRegistrationRequest := NodeRegistrationRequest{
		NumCores: runtime.NumCPU(),
	}
	json.NewEncoder(&body).Encode(nodeRegistrationRequest)

	for {
		orchestratorDetails, err := dc.registerNode(registerNodeURL, &body)
		if err != nil {
			logger.Errorf("[dncclient] Failed to register node: %s with error: %+v", dc.nodeID, err)
			// TODO: make this interval configurable
			time.Sleep(registerNodeRetryInterval)
			continue
		}

		logger.Printf("[dncclient] Successfully registered node: %s", dc.nodeID)
		return &orchestratorDetails
	}
}

func (dc *DNCClient) registerNode(url string, body io.Reader) (cns.SetOrchestratorTypeRequest, error) {
	var orchestratorDetails cns.SetOrchestratorTypeRequest
	token, err := dc.getOAuthToken()
	if err != nil {
		return orchestratorDetails, err
	}

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return orchestratorDetails, err
	}

	req.Header.Set(httpReqHeaderKeyAuth, "Bearer "+token)
	req.Header.Set(httpReqHeaderKeyAccept, acn.JsonContent)
	response, err := dc.httpClient.Do(req)
	if err != nil {
		return orchestratorDetails, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return orchestratorDetails,
			fmt.Errorf("[dncclient] Failed to register node with http status code: %d", response.StatusCode)
	}

	_ = json.NewDecoder(response.Body).Decode(&orchestratorDetails)
	return orchestratorDetails, nil
}

// SyncNodeNcStatus retrieves the NCs scheduled on this node by DNC
func (dc *DNCClient) SyncNodeNcStatus() (cns.NodeInfoResponse, error) {
	var (
		syncNodeNcStatusURL = fmt.Sprintf(syncNodeNetworkContainersURLFmt,
			dc.dncEndpointDns, dc.infraVnet, dc.nodeID, dncAPIVersion)
		nodeInfoResponse cns.NodeInfoResponse
	)

	logger.Printf("[dncclient] SyncNodeNcStatus: Node: %s, InfraVnet: %s", dc.nodeID, dc.infraVnet)

	token, err := dc.getOAuthToken()
	if err != nil {
		return nodeInfoResponse, err
	}

	req, err := http.NewRequest(http.MethodGet, syncNodeNcStatusURL, bytes.NewBuffer(nil))
	if err != nil {
		return nodeInfoResponse, err
	}

	req.Header.Set(httpReqHeaderKeyAuth, "Bearer "+token)
	req.Header.Set(httpReqHeaderKeyAccept, acn.JsonContent)
	response, err := dc.httpClient.Do(req)
	if err != nil {
		return nodeInfoResponse, err
	}

	if response.StatusCode == http.StatusOK {
		err = json.NewDecoder(response.Body).Decode(&nodeInfoResponse)
	} else {
		/*
			var jsonErr api.jsonErr
			err = json.NewDecoder(response.Body).Decode(&jsonErr)
			if err == nil {
				err = fmt.Errorf("%s")
			}
		*/
	}
	response.Body.Close()

	return nodeInfoResponse, err
}
