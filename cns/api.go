// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package cns

import (
	"github.com/Azure/azure-container-networking/ipam"
	"github.com/Azure/azure-container-networking/network"
)

// Container Network Service remote API Contract
const (
	SetEnvironmentPath          = "/network/environment"
	CreateNetworkPath           = "/network/create" // this should be changed to dockercreate
	DeleteNetworkPath           = "/network/delete"
	ReserveIPAddressPath        = "/network/ip/reserve"
	ReleaseIPAddressPath        = "/network/ip/release"
	GetHostLocalIPPath          = "/network/ip/hostlocal"
	GetIPAddressUtilizationPath = "/network/ip/utilization"
	GetUnhealthyIPAddressesPath = "/network/ipaddresses/unhealthy"
	GetHealthReportPath         = "/network/health"
	AddExtIfRequestPath         = "/network/addextif"

	CreateNewNetworkPath        = "/network/manager/nw/create"
	DeleteNewNetworkPath        = "/network/manager/nw/delete"
	GetNetworkInfoPath          = "/network/manager/nw/getinfo"
	CreateEndpointPath          = "/network/manager/endpoint/create"
	DeleteEndpointPath          = "/network/manager/endpoint/delete"
	AttachEndpointPath          = "/network/manager/endpoint/attach"
	DetachEndpointPath          = "/network/manager/endpoint/detach"
	GetEndpointInfoPath         = "/network/manager/endpoint/getinfo"
	StartSourcePath             = "/network/ipam/startsource"
	StopSourcePath              = "/network/ipam/stopsource"
	GetDefaultAddressSpacesPath = "/network/ipam/getdefaultaddressspaces"
	RequestPoolPath             = "/network/ipam/requestpool"
	ReleasePoolPath             = "/network/ipam/releasepool"
	GetPoolInfoPath             = "/network/ipam/getpoolinfo"
	RequestAddressPath          = "/network/ipam/requestaddress"
	ReleaseAddressPath          = "/network/ipam/releaseaddress"

	V1Prefix = "/v0.1"
	V2Prefix = "/v0.2"
)

// SetEnvironmentRequest describes the Request to set the environment in CNS.
type SetEnvironmentRequest struct {
	Location    string
	NetworkType string
}

// OverlayConfiguration describes configuration for all the nodes that are part of overlay.
type OverlayConfiguration struct {
	NodeCount     int
	LocalNodeIP   string
	OverlaySubent Subnet
	NodeConfig    []NodeConfiguration
}

// CreateNetworkRequest describes request to create the network.
type CreateNetworkRequest struct {
	NetworkName          string
	OverlayConfiguration OverlayConfiguration
	Options              map[string]interface{}
}

// DeleteNetworkRequest describes request to delete the network.
type DeleteNetworkRequest struct {
	NetworkName string
}

// ReserveIPAddressRequest describes request to reserve an IP Address
type ReserveIPAddressRequest struct {
	ReservationID string
}

// ReserveIPAddressResponse describes response to reserve an IP address.
type ReserveIPAddressResponse struct {
	Response  Response
	IPAddress string
}

// ReleaseIPAddressRequest describes request to release an IP Address.
type ReleaseIPAddressRequest struct {
	ReservationID string
}

// IPAddressesUtilizationResponse describes response for ip address utilization.
type IPAddressesUtilizationResponse struct {
	Response  Response
	Available int
	Reserved  int
	Unhealthy int
}

// GetIPAddressesResponse describes response containing requested ip addresses.
type GetIPAddressesResponse struct {
	Response    Response
	IPAddresses []string
}

// HostLocalIPAddressResponse describes reponse that returns the host local IP Address.
type HostLocalIPAddressResponse struct {
	Response  Response
	IPAddress string
}

// Subnet contains the ip address and the number of bits in prefix.
type Subnet struct {
	IPAddress    string
	PrefixLength int
}

// NodeConfiguration describes confguration for a node in overlay network.
type NodeConfiguration struct {
	NodeIP     string
	NodeID     string
	NodeSubnet Subnet
}

// Response describes generic response from CNS.
type Response struct {
	ReturnCode int
	Message    string
}

// OptionMap describes generic options that can be passed to CNS.
type OptionMap map[string]interface{}

// Response to a failed request.
type errorResponse struct {
	Err string
}

// GetNetworkInfoRequest describes request to get the network info.
type GetNetworkInfoRequest struct {
	NetworkName string
}

// GetNetworkInfoResponse describes response to get the network info.
type GetNetworkInfoResponse struct {
	Response Response
	NwInfo   *network.NetworkInfo
}

// CreateEndpointRequest describes request to create endpoint.
type CreateEndpointRequest struct {
	NetworkName string
	EpInfo      *network.EndpointInfo
}

// CreateNewNetworkRequest describes request to create network.
type CreateNewNetworkRequest struct {
	NwInfo *network.NetworkInfo
}

// DeleteNewNetworkRequest describes request to create network.
type DeleteNewNetworkRequest struct {
	NetworkName string
}

// AddExtIfRequest describes request to add external interface.
type AddExtIfRequest struct {
	MasterIfName string
	SubnetPrefix string
}

// DeleteEndpointRequest describes request to delete endpoint.
type DeleteEndpointRequest struct {
	NetworkName string
	EndpointId  string
}

// GetEndpointInfoRequest describes request to get endpoint info.
type GetEndpointInfoRequest struct {
	NetworkName string
	EndpointId  string
}

// GetEndpointInfoResponse describes response for get endpoint info request.
type GetEndpointInfoResponse struct {
	Response Response
	EpInfo   *network.EndpointInfo
}

// AttachEndpointRequest describes request to attach an endpoint.
type AttachEndpointRequest struct {
	NetworkName string
	EndpointId  string
	SandboxKey  string
}

// AttachEndpointResponse describes response for attach endpoint request.
type AttachEndpointResponse struct {
	Response Response
	EpInfo   *network.EndpointInfo
}

// DetachEndpointRequest describes request to detach an endpoint.
type DetachEndpointRequest struct {
	NetworkName string
	EndpointId  string
}

// StartSourceRequest describes request to ???.
type StartSourceRequest struct {
	Options map[string]interface{}
}

// RequestPoolRequest describes request to ???.
type RequestPoolRequest struct {
	AsID      string
	PoolID    string
	SubPoolID string
	Options   map[string]string
	V6        bool
}

// RequestPoolResponse describes response for RequestPool request.
type RequestPoolResponse struct {
	Response Response
	PoolID   string
	Subnet   string
}

// ReleasePoolRequest describes request to ???.
type ReleasePoolRequest struct {
	AsID   string
	PoolID string
}

// RequestAddressRequest describes request to ???.
type RequestAddressRequest struct {
	AsID    string
	PoolID  string
	Address string
	Options map[string]string
}

// RequestAddressResponse describes response for RequestAddress request.
type RequestAddressResponse struct {
	Response Response
	Address  string
}

// ReleaseAddressRequest describes request to ???.
type ReleaseAddressRequest struct {
	AsID    string
	PoolID  string
	Address string
	Options map[string]string
}

// GetPoolInfoRequest describes request to ???.
type GetPoolInfoRequest struct {
	AsID   string
	PoolID string
}

// GetPoolInfoResponse describes response for GetPoolInfo request.
type GetPoolInfoResponse struct {
	Response Response
	ApInfo   *ipam.AddressPoolInfo
}

// GetDefaultAddressSpacesResponse describes response for GetDefaultAddressSpaces request.
type GetDefaultAddressSpacesResponse struct {
	Response                  Response
	LocalDefaultAddressSpace  string
	GlobalDefaultAddressSpace string
}
