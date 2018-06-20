// Copyright 2018 Microsoft. All rights reserved.
// MIT License

package cnsclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/ipam"
	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/network"
)

// cns client manages the communication between a plugin and cns rest server
type client struct {
	serverURL       string
	httpClient      *http.Client
	usePersistStore bool
}

// Client API for cns
type Client interface {
	AddExternalInterface(masterIfName, subnetPrefix string) error
	CreateNetwork(nwInfo *network.NetworkInfo) error
	DeleteNetwork(networkId string) error
	GetNetworkInfo(networkId string) (*network.NetworkInfo, error)
	CreateEndpoint(networkId string, epInfo *network.EndpointInfo) error
	DeleteEndpoint(networkId, endpointId string) error
	AttachEndpoint(networkId string, endpointId string, sandboxKey string) (*network.EndpointInfo, error)
	DetachEndpoint(networkId string, endpointId string) error
	GetEndpointInfo(networkId, endpointId string) (*network.EndpointInfo, error)

	StartSource(options map[string]interface{}) error
	RequestPool(asId, poolId, subPoolId string, options map[string]string, v6 bool) (string, string, error)
	ReleasePool(asId, poolId string) error
	GetPoolInfo(asId, poolId string) (*ipam.AddressPoolInfo, error)
	RequestAddress(asId, poolId, address string, options map[string]string) (string, error)
	ReleaseAddress(asId, poolId, address string, options map[string]string) error
	GetDefaultAddressSpaces() (string, string, error)

	PostCnsRequest(httpReqPayload interface{}, cnsResourcePath string, cnsResponse interface{}) error
	SetPersistStoreUsage(usePersistentStore bool) error
}

// NewClient returns cns client that communicates with cns server
func NewClient(plugin string) Client {

	var persistStore bool
	if plugin == "cni" {
		persistStore = false
	} else {
		persistStore = true
	}

	client := &client{
		serverURL:       "http://localhost:10090",
		httpClient:      &http.Client{},
		usePersistStore: persistStore,
	}

	return client
}

// PostCnsRequest makes the HTTP POST requests to cns server
func (cnsClient *client) PostCnsRequest(payload interface{}, path string, resp interface{}) error {
	var body bytes.Buffer
	var err error
	var res *http.Response

	json.NewEncoder(&body).Encode(payload)

	res, err = cnsClient.httpClient.Post(cnsClient.serverURL+path, "application/json", &body)
	// TODO: need to check the error for absence of azure-cns process
	if err != nil {
		log.Printf("[cns client] Starting azure-cns")

		dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
		args := fmt.Sprintf("--use-persist-store=%v", cnsClient.usePersistStore)

		if runtime.GOOS == "linux" {
			cmd := exec.Command(dir+"/azure-cns", args)
			err = cmd.Start()
		} else {
			cmd := exec.Command(dir+"\\azure-cns.exe", args)
			err = cmd.Start()
		}

		if err != nil {
			log.Printf("[cns client] Failed to start azure-cns server")
			return fmt.Errorf("cns server unavailable")
		}

		// Sleep for 100ms to allow CNS server to be up and running
		time.Sleep(100 * time.Millisecond)

		res, err = cnsClient.httpClient.Post(cnsClient.serverURL+path, "application/json", &body)
		if err != nil {
			return fmt.Errorf("cns server unavailable")
		}
	}

	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			return fmt.Errorf("Error parsing response %v : %v", res.Body, err.Error())
		}
	} else {
		return fmt.Errorf("HTTP POST returned status code %v", res.StatusCode)
	}
	return nil
}

// SetPersistStoreUsage set the flag to use persistent store
func (cnsClient *client) SetPersistStoreUsage(usePersistentStore bool) error {
	var err error
	var resp cns.Response

	cnsClient.usePersistStore = usePersistentStore

	payload := &cns.SetPersistStoreUsageRequest{
		UsePersistStore: usePersistentStore,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.SetPersistStoreUsagePath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for SetPersistStoreUsage failed " + err.Error())
	} else if resp.ReturnCode != 0 {
		log.Printf("[cns client] SetPersistStoreUsage failed: %v", resp.Message)
		err = errors.New(resp.Message)
	}

	return err
}

// GetNetworkInfo returns information about the given network.
func (cnsClient *client) GetNetworkInfo(networkId string) (*network.NetworkInfo, error) {
	var err error
	var resp cns.GetNetworkInfoResponse

	payload := &cns.GetNetworkInfoRequest{
		NetworkName: networkId,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.GetNetworkInfoPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for GetNetworkInfo failed " + err.Error())
		return nil, err
	}

	if resp.Response.ReturnCode != 0 {
		log.Printf("[cns client] GetNetworkInfo failed: %v", resp.Response.Message)
		err = errors.New(resp.Response.Message)
	}

	return resp.NwInfo, err
}

// GetEndpointInfo returns information about the given endpoint.
func (cnsClient *client) GetEndpointInfo(networkId, endpointId string) (*network.EndpointInfo, error) {
	var err error
	var resp cns.GetEndpointInfoResponse

	payload := &cns.GetEndpointInfoRequest{
		NetworkName: networkId,
		EndpointId:  endpointId,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.GetEndpointInfoPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for GetEndpointInfo failed " + err.Error())
		return nil, err
	}

	if resp.Response.ReturnCode != 0 {
		log.Printf("[cns client] GetEndpointInfo failed: %v", resp.Response.Message)
		err = errors.New(resp.Response.Message)
	}

	return resp.EpInfo, err
}

// AddExternalInterface adds a host interface to the list of available external interfaces.
func (cnsClient *client) AddExternalInterface(masterIfName, subnetPrefix string) error {
	var err error
	var resp cns.Response

	payload := &cns.AddExtIfRequest{
		MasterIfName: masterIfName,
		SubnetPrefix: subnetPrefix,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.AddExtIfRequestPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for AddExternalInterface failed " + err.Error())
	} else if resp.ReturnCode != 0 {
		log.Printf("[cns client] AddExternalInterface failed: %v", resp.Message)
		err = errors.New(resp.Message)
	}

	return err
}

// CreateNetwork creates a new container network.
func (cnsClient *client) CreateNetwork(nwInfo *network.NetworkInfo) error {
	var err error
	var resp cns.Response
	payload := &cns.CreateNewNetworkRequest{
		NwInfo: nwInfo,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.CreateNewNetworkPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for CreateNetwork failed " + err.Error())
	} else if resp.ReturnCode != 0 {
		log.Printf("[cns client] CreateNetwork failed: %v", resp.Message)
		err = errors.New(resp.Message)
	}

	return err
}

// DeleteNetwork deletes an existing container network.
func (cnsClient *client) DeleteNetwork(networkId string) error {
	var err error
	var resp cns.Response
	payload := &cns.DeleteNewNetworkRequest{
		NetworkName: networkId,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.DeleteNewNetworkPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for DeleteNetwork failed " + err.Error())
	} else if resp.ReturnCode != 0 {
		log.Printf("[cns client] DeleteNetwork failed: %v", resp.Message)
		err = errors.New(resp.Message)
	}

	return err
}

// CreateEndpoint creates a new container endpoint.
func (cnsClient *client) CreateEndpoint(networkId string, epInfo *network.EndpointInfo) error {
	var err error
	var resp cns.Response

	payload := &cns.CreateEndpointRequest{
		NetworkName: networkId,
		EpInfo:      epInfo,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.CreateEndpointPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for CreateEndpoint failed " + err.Error())
	} else if resp.ReturnCode != 0 {
		log.Printf("[cns client] CreateEndpoint failed: %v", resp.Message)
		err = errors.New(resp.Message)
	}

	return err
}

// DeleteEndpoint deletes an existing container endpoint.
func (cnsClient *client) DeleteEndpoint(networkId, endpointId string) error {
	var err error
	var resp cns.Response

	payload := &cns.DeleteEndpointRequest{
		NetworkName: networkId,
		EndpointId:  endpointId,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.DeleteEndpointPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for DeleteEndpoint failed " + err.Error())
	} else if resp.ReturnCode != 0 {
		log.Printf("[cns client] DeleteEndpoint failed: %v", resp.Message)
		err = errors.New(resp.Message)
	}

	return err
}

// AttachEndpoint attaches an endpoint to a sandbox.
func (cnsClient *client) AttachEndpoint(networkId string, endpointId string, sandboxKey string) (*network.EndpointInfo, error) {
	var err error
	var resp cns.AttachEndpointResponse

	payload := &cns.AttachEndpointRequest{
		NetworkName: networkId,
		EndpointId:  endpointId,
		SandboxKey:  sandboxKey,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.AttachEndpointPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for AttachEndpoint failed " + err.Error())
		return nil, err
	}

	if resp.Response.ReturnCode != 0 {
		log.Printf("[cns client] AttachEndpoint failed: %v", resp.Response.Message)
		err = errors.New(resp.Response.Message)
	}

	return resp.EpInfo, err
}

// DetachEndpoint detaches an endpoint from its sandbox.
func (cnsClient *client) DetachEndpoint(networkId string, endpointId string) error {
	var err error
	var resp cns.Response

	payload := &cns.DetachEndpointRequest{
		NetworkName: networkId,
		EndpointId:  endpointId,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.DetachEndpointPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for DetachEndpoint failed " + err.Error())
	} else if resp.ReturnCode != 0 {
		log.Printf("[cns client] DetachEndpoint failed: %v", resp.Message)
		err = errors.New(resp.Message)
	}

	return err
}

// Starts configuration source.
func (cnsClient *client) StartSource(options map[string]interface{}) error {
	var err error
	var resp cns.Response

	payload := &cns.StartSourceRequest{
		Options: options,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.StartSourcePath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for StartSource failed " + err.Error())
	} else if resp.ReturnCode != 0 {
		log.Printf("[cns client] StartSource failed: %v", resp.Message)
		err = errors.New(resp.Message)
	}

	return err
}

// RequestPool reserves an address pool.
func (cnsClient *client) RequestPool(asId, poolId, subPoolId string, options map[string]string, v6 bool) (string, string, error) {
	var err error
	var resp cns.RequestPoolResponse

	payload := &cns.RequestPoolRequest{
		AsID:      asId,
		PoolID:    poolId,
		SubPoolID: subPoolId,
		Options:   options,
		V6:        false,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.RequestPoolPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for RequestPool failed " + err.Error())
		return "", "", err
	}

	if resp.Response.ReturnCode != 0 {
		log.Printf("[cns client] RequestPool failed: %v", resp.Response.Message)
		err = errors.New(resp.Response.Message)
	}

	return resp.PoolID, resp.Subnet, err
}

// ReleasePool releases a previously reserved address pool.
func (cnsClient *client) ReleasePool(asId, poolId string) error {
	var err error
	var resp cns.Response

	payload := &cns.ReleasePoolRequest{
		AsID:   asId,
		PoolID: poolId,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.ReleasePoolPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for ReleasePool failed " + err.Error())
	} else if resp.ReturnCode != 0 {
		log.Printf("[cns client] ReleasePool failed: %v", resp.Message)
		err = errors.New(resp.Message)
	}

	return err
}

// RequestAddress reserves a new address from the address pool.
func (cnsClient *client) RequestAddress(asId, poolId, address string, options map[string]string) (string, error) {
	var err error
	var resp cns.RequestAddressResponse

	payload := &cns.RequestAddressRequest{
		AsID:    asId,
		PoolID:  poolId,
		Address: address,
		Options: options,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.RequestAddressPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for RequestAddress failed " + err.Error())
		return "", err
	}

	if resp.Response.ReturnCode != 0 {
		log.Printf("[cns client] RequestAddress failed: %v", resp.Response.Message)
		err = errors.New(resp.Response.Message)
	}

	return resp.Address, err
}

// ReleaseAddress releases a previously reserved address.
func (cnsClient *client) ReleaseAddress(asId, poolId, address string, options map[string]string) error {
	var err error
	var resp cns.Response

	payload := &cns.ReleaseAddressRequest{
		AsID:    asId,
		PoolID:  poolId,
		Address: address,
		Options: options,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.ReleaseAddressPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for ReleaseAddress failed " + err.Error())
	} else if resp.ReturnCode != 0 {
		log.Printf("[cns client] ReleaseAddress failed: %v", resp.Message)
		err = errors.New(resp.Message)
	}

	return err
}

// GetPoolInfo returns information about the given address pool.
func (cnsClient *client) GetPoolInfo(asId, poolId string) (*ipam.AddressPoolInfo, error) {
	var err error
	var resp cns.GetPoolInfoResponse

	payload := &cns.GetPoolInfoRequest{
		AsID:   asId,
		PoolID: poolId,
	}

	if err = cnsClient.PostCnsRequest(payload, cns.GetPoolInfoPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for GetPoolInfo failed " + err.Error())
		return nil, err
	}

	if resp.Response.ReturnCode != 0 {
		log.Printf("[cns client] GetPoolInfo failed: %v", resp.Response.Message)
		err = errors.New(resp.Response.Message)
	}

	return resp.ApInfo, err
}

// GetDefaultAddressSpaces returns the default local and global address space IDs
func (cnsClient *client) GetDefaultAddressSpaces() (string, string, error) {
	var err error
	var resp cns.GetDefaultAddressSpacesResponse

	if err = cnsClient.PostCnsRequest(nil, cns.GetDefaultAddressSpacesPath, &resp); err != nil {
		log.Printf("[cns client] PostCnsRequest for GetDefaultAddressSpaces failed " + err.Error())
		return "", "", err
	}

	if resp.Response.ReturnCode != 0 {
		log.Printf("[cns client] GetDefaultAddressSpaces failed: %v", resp.Response.Message)
		err = errors.New(resp.Response.Message)
	}

	return resp.LocalDefaultAddressSpace, resp.GlobalDefaultAddressSpace, err
}
