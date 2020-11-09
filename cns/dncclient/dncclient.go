package dncclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	//"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/configuration"
	"github.com/Azure/azure-container-networking/cns/logger"
	acn "github.com/Azure/azure-container-networking/common"

	"context"

	ad "github.com/Azure/azure-container-networking/cns/dncclient/activedirectory"
)

const (
	// RegisterNodeURLFmt: /networks/{infraNetworkID}/node/{nodeID}
	registerNodeURLFmt = "%s/networks/%s/node/%s%s"
	// SyncNodeNetworkContainersURLFmt: /networks/{infraNetworkID}/node/{nodeID}/networkcontainers
	syncNodeNetworkContainersURLFmt = "%s/networks/%s/node/%s/networkcontainers%s"

	dncAPIVersion             = "?api-version=2018-03-01"
	registerNodeRetryInterval = 5 * time.Second
	dncResourceEndpoint       = "https://management.azure.com/"

	httpReqHeaderKeyAuth   = "Authorization"
	httpReqHeaderKeyAccept = "Accept"
)

type DNCClient struct {
	dncEndpointDns      string
	infraVnet           string
	nodeID              string
	nodeManagedIdentity string
	tokenFetcher        ad.TokenFetcher
}

// NodeRegistrationRequest - Struct to hold node registration request.
type NodeRegistrationRequest struct {
	NumCores int `json:"NumCores"`
}

// NewDNCClient creates a new DNCClient
func NewDNCClient(
	managedSettings *configuration.ManagedSettings) (*DNCClient, error) {
	//clientID := "8ad8b90c-f31b-4c6e-ac7a-37b65522a153"
	tokenFetcher, err := getTokenFetcher(managedSettings.NodeManagedIdentity)
	if err != nil {
		return nil, fmt.Errorf("Failed to create DNC client due to error: %v", err)
	}

	client := &DNCClient{
		dncEndpointDns:      managedSettings.DncEndpointDns,
		infraVnet:           managedSettings.InfrastructureNetworkID,
		nodeID:              managedSettings.NodeID,
		nodeManagedIdentity: managedSettings.NodeManagedIdentity,
		tokenFetcher:        tokenFetcher,
	}

	return client, nil
}

func getTokenFetcher(
	nodeManagedIdentity string) (ad.TokenFetcher, error) {
	if nodeManagedIdentity != "" {
		return &ad.MSITokenFetcher{ClientID: nodeManagedIdentity}, nil
	}

	return nil, fmt.Errorf("Empty Node managed identity")
}

func (dc *DNCClient) getFreshToken() (string, error) {
	spt, err := dc.tokenFetcher.GetServicePrincipalToken(dncResourceEndpoint)
	if err != nil {
		return "", fmt.Errorf("Failed to get Service Principle token. Error: %v", err)
	}

	token, err := ad.GetFreshToken(context.Background(), spt)
	if err != nil {
		return "", fmt.Errorf("Failed to get AAD token. Error: %v", err)
	}

	return token, nil
}

/*
func Temp() error {
	tokenFetcher, err := getTokenFetcher()
	if err != nil {
		logger.Printf("[tempdebug] err: %v", err)
		return err
	}

	spt, err := tokenFetcher.GetServicePrincipalToken("https://management.azure.com/")
	if err != nil {
		logger.Printf("[tempdebug2] err: %v", err)
		return err
	}

	ctx := context.Background()
	token, err := ad.GetFreshToken(ctx, spt)
	if err != nil {
		logger.Printf("[tempdebug3] err: %v", err)
		return err
	}

	logger.Printf("[tempdebug] success: %v", token)
	return nil
}
*/

// RegisterNode registers the node with managed DNC
func (dc *DNCClient) RegisterNode() *cns.SetOrchestratorTypeRequest {
	logger.Printf("[dncclient] Registering node: %s with Infrastructure Network: %s dncEP: %s",
		dc.nodeID, dc.infraVnet, dc.dncEndpointDns)

	var (
		registerNodeURL = fmt.Sprintf(registerNodeURLFmt, dc.dncEndpointDns,
			dc.infraVnet, dc.nodeID, dncAPIVersion)
		body  bytes.Buffer
		httpc = acn.GetHttpClient()
	)

	// Create a body with number of CPU cores
	nodeRegistrationRequest := NodeRegistrationRequest{
		NumCores: runtime.NumCPU(),
	}
	json.NewEncoder(&body).Encode(nodeRegistrationRequest)

	for {
		orchestratorDetails, err := dc.registerNode(httpc, registerNodeURL, &body)
		if err != nil {
			logger.Errorf("[dncclient] Failed to register node: %s with error: %+v", dc.nodeID, err)
			// todo: make this interval configurable
			time.Sleep(registerNodeRetryInterval)
			continue
		}

		logger.Printf("[dncclient] Successfully registered node: %s", dc.nodeID)
		return &orchestratorDetails
	}
}

func (dc *DNCClient) registerNode(httpCl *http.Client, url string, body io.Reader) (cns.SetOrchestratorTypeRequest, error) {
	var orchestratorDetails cns.SetOrchestratorTypeRequest
	token, err := dc.getFreshToken()
	if err != nil {
		return orchestratorDetails, err
	}

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return orchestratorDetails, err
	}

	req.Header.Set(httpReqHeaderKeyAuth, "Bearer "+token)
	req.Header.Set(httpReqHeaderKeyAccept, acn.JsonContent)
	response, err := httpCl.Do(req)
	//response, err := httpCl.Post(url, acn.JsonContent, body)
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
		httpCl           = acn.GetHttpClient()
	)

	logger.Printf("[dncclient] SyncNodeNcStatus: Node: %s, InfraVnet: %s", dc.nodeID, dc.infraVnet)

	token, err := dc.getFreshToken()
	if err != nil {
		return nodeInfoResponse, err
	}

	req, err := http.NewRequest(http.MethodGet, syncNodeNcStatusURL, bytes.NewBuffer(nil))
	if err != nil {
		return nodeInfoResponse, err
	}

	req.Header.Set(httpReqHeaderKeyAuth, "Bearer "+token)
	req.Header.Set(httpReqHeaderKeyAccept, acn.JsonContent)
	response, err := httpCl.Do(req)
	//response, err := httpc.Get(syncNodeNcStatusURL)
	if err != nil {
		return nodeInfoResponse, err
	}

	if response.StatusCode == http.StatusOK {
		err = json.NewDecoder(response.Body).Decode(&nodeInfoResponse)
	} else {
		err = fmt.Errorf("%d", response.StatusCode)
	}
	response.Body.Close()

	return nodeInfoResponse, err
}
