// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package ipam

import (
	"net/http"

	"github.com/Azure/azure-container-networking/cnm"
	"github.com/Azure/azure-container-networking/cns/client"
	"github.com/Azure/azure-container-networking/common"
	"github.com/Azure/azure-container-networking/ipam"
	"github.com/Azure/azure-container-networking/log"
)

const (
	// Plugin name.
	name = "azure-vnet-ipam"

	// Plugin capabilities reported to libnetwork.
	requiresMACAddress    = false
	requiresRequestReplay = false
)

// IpamPlugin represents a CNM (libnetwork) IPAM plugin.
type ipamPlugin struct {
	*cnm.Plugin
	cnsClient cnsclient.Client
}

type IpamPlugin interface {
	common.PluginApi
}

// NewPlugin creates a new IpamPlugin object.
func NewPlugin(config *common.PluginConfig) (IpamPlugin, error) {
	// Setup base plugin.
	plugin, err := cnm.NewPlugin(name, config.Version, EndpointType)
	if err != nil {
		return nil, err
	}

	client := cnsclient.NewClient("cnm")

	config.IpamApi = nil

	return &ipamPlugin{
		Plugin:    plugin,
		cnsClient: client,
	}, nil
}

// Start starts the plugin.
func (plugin *ipamPlugin) Start(config *common.PluginConfig) error {
	var err error
	// Initialize cns client
	if err = plugin.cnsClient.SetPersistStoreUsage(true); err != nil {
		log.Printf("[ipam] Failed to SetPersistStoreUsage for cns client, err: %v.", err)
		return err
	}

	// Initialize base plugin.
	err = plugin.Initialize(config)
	if err != nil {
		log.Printf("[ipam] Failed to initialize base plugin, err:%v.", err)
		return err
	}

	// Add protocol handlers.
	listener := plugin.Listener
	listener.AddEndpoint(plugin.EndpointType)
	listener.AddHandler(GetCapabilitiesPath, plugin.getCapabilities)
	listener.AddHandler(GetAddressSpacesPath, plugin.getDefaultAddressSpaces)
	listener.AddHandler(RequestPoolPath, plugin.requestPool)
	listener.AddHandler(ReleasePoolPath, plugin.releasePool)
	listener.AddHandler(GetPoolInfoPath, plugin.getPoolInfo)
	listener.AddHandler(RequestAddressPath, plugin.requestAddress)
	listener.AddHandler(ReleaseAddressPath, plugin.releaseAddress)

	// Plugin is ready to be discovered.
	err = plugin.EnableDiscovery()
	if err != nil {
		log.Printf("[ipam] Failed to enable discovery: %v.", err)
		return err
	}

	log.Printf("[ipam] Plugin started.")

	return nil
}

// Stop stops the plugin.
func (plugin *ipamPlugin) Stop() {
	plugin.DisableDiscovery()
	plugin.Uninitialize()
	log.Printf("[ipam] Plugin stopped.")
}

//
// Libnetwork remote IPAM API implementation
// https://github.com/docker/libnetwork/blob/master/docs/ipam.md
//

// Handles GetCapabilities requests.
func (plugin *ipamPlugin) getCapabilities(w http.ResponseWriter, r *http.Request) {
	var req GetCapabilitiesRequest

	log.Request(plugin.Name, &req, nil)

	resp := GetCapabilitiesResponse{
		RequiresMACAddress:    requiresMACAddress,
		RequiresRequestReplay: requiresRequestReplay,
	}

	err := plugin.Listener.Encode(w, &resp)

	log.Response(plugin.Name, &resp, err)
}

// Handles GetDefaultAddressSpaces requests.
func (plugin *ipamPlugin) getDefaultAddressSpaces(w http.ResponseWriter, r *http.Request) {
	var req GetDefaultAddressSpacesRequest
	var resp GetDefaultAddressSpacesResponse

	log.Request(plugin.Name, &req, nil)

	localId, globalId, err := plugin.cnsClient.GetDefaultAddressSpaces()
	if err != nil {
		plugin.SendErrorResponse(w, err)
		return
	}

	resp.LocalDefaultAddressSpace = localId
	resp.GlobalDefaultAddressSpace = globalId

	err = plugin.Listener.Encode(w, &resp)

	log.Response(plugin.Name, &resp, err)
}

// Handles RequestPool requests.
func (plugin *ipamPlugin) requestPool(w http.ResponseWriter, r *http.Request) {
	var req RequestPoolRequest

	// Decode request.
	err := plugin.Listener.Decode(w, r, &req)
	log.Request(plugin.Name, &req, err)
	if err != nil {
		return
	}

	// Process request.
	poolId, subnet, err := plugin.cnsClient.RequestPool(req.AddressSpace, req.Pool, req.SubPool, req.Options, req.V6)
	if err != nil {
		plugin.SendErrorResponse(w, err)
		return
	}

	// Encode response.
	data := make(map[string]string)
	poolId = ipam.NewAddressPoolId(req.AddressSpace, poolId, "").String()
	resp := RequestPoolResponse{PoolID: poolId, Pool: subnet, Data: data}

	err = plugin.Listener.Encode(w, &resp)

	log.Response(plugin.Name, &resp, err)
}

// Handles ReleasePool requests.
func (plugin *ipamPlugin) releasePool(w http.ResponseWriter, r *http.Request) {
	var req ReleasePoolRequest

	// Decode request.
	err := plugin.Listener.Decode(w, r, &req)
	log.Request(plugin.Name, &req, err)
	if err != nil {
		return
	}

	// Process request.
	poolId, err := ipam.NewAddressPoolIdFromString(req.PoolID)
	if err != nil {
		plugin.SendErrorResponse(w, err)
		return
	}

	err = plugin.cnsClient.ReleasePool(poolId.AsId, poolId.Subnet)
	if err != nil {
		plugin.SendErrorResponse(w, err)
		return
	}

	// Encode response.
	resp := ReleasePoolResponse{}

	err = plugin.Listener.Encode(w, &resp)

	log.Response(plugin.Name, &resp, err)
}

// Handles GetPoolInfo requests.
func (plugin *ipamPlugin) getPoolInfo(w http.ResponseWriter, r *http.Request) {
	var req GetPoolInfoRequest

	// Decode request.
	err := plugin.Listener.Decode(w, r, &req)
	log.Request(plugin.Name, &req, err)
	if err != nil {
		return
	}

	// Process request.
	poolId, err := ipam.NewAddressPoolIdFromString(req.PoolID)
	if err != nil {
		plugin.SendErrorResponse(w, err)
		return
	}

	apInfo, err := plugin.cnsClient.GetPoolInfo(poolId.AsId, poolId.Subnet)
	if err != nil {
		plugin.SendErrorResponse(w, err)
		return
	}

	// Encode response.
	resp := GetPoolInfoResponse{
		Capacity:  apInfo.Capacity,
		Available: apInfo.Available,
	}

	for _, addr := range apInfo.UnhealthyAddrs {
		resp.UnhealthyAddresses = append(resp.UnhealthyAddresses, addr.String())
	}

	err = plugin.Listener.Encode(w, &resp)

	log.Response(plugin.Name, &resp, err)
}

// Handles RequestAddress requests.
func (plugin *ipamPlugin) requestAddress(w http.ResponseWriter, r *http.Request) {
	var req RequestAddressRequest

	// Decode request.
	err := plugin.Listener.Decode(w, r, &req)
	log.Request(plugin.Name, &req, err)
	if err != nil {
		return
	}

	// Process request.
	poolId, err := ipam.NewAddressPoolIdFromString(req.PoolID)
	if err != nil {
		plugin.SendErrorResponse(w, err)
		return
	}

	// Convert libnetwork IPAM options to core IPAM options.
	options := make(map[string]string)
	if req.Options[OptAddressType] == OptAddressTypeGateway {
		options[ipam.OptAddressType] = ipam.OptAddressTypeGateway
	}

	options[ipam.OptAddressID] = req.Options[ipam.OptAddressID]

	addr, err := plugin.cnsClient.RequestAddress(poolId.AsId, poolId.Subnet, req.Address, options)
	if err != nil {
		plugin.SendErrorResponse(w, err)
		return
	}

	// Encode response.
	data := make(map[string]string)
	resp := RequestAddressResponse{Address: addr, Data: data}

	err = plugin.Listener.Encode(w, &resp)

	log.Response(plugin.Name, &resp, err)
}

// Handles ReleaseAddress requests.
func (plugin *ipamPlugin) releaseAddress(w http.ResponseWriter, r *http.Request) {
	var req ReleaseAddressRequest

	// Decode request.
	err := plugin.Listener.Decode(w, r, &req)
	log.Request(plugin.Name, &req, err)
	if err != nil {
		return
	}

	// Process request.
	poolId, err := ipam.NewAddressPoolIdFromString(req.PoolID)
	if err != nil {
		plugin.SendErrorResponse(w, err)
		return
	}

	err = plugin.cnsClient.ReleaseAddress(poolId.AsId, poolId.Subnet, req.Address, req.Options)
	if err != nil {
		plugin.SendErrorResponse(w, err)
		return
	}

	// Encode response.
	resp := ReleaseAddressResponse{}

	err = plugin.Listener.Encode(w, &resp)

	log.Response(plugin.Name, &resp, err)
}
