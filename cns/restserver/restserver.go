// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package restserver

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/common"
	"github.com/Azure/azure-container-networking/cns/dockerclient"
	"github.com/Azure/azure-container-networking/cns/imdsclient"
	"github.com/Azure/azure-container-networking/cns/ipamclient"
	"github.com/Azure/azure-container-networking/cns/networkcontainers"
	"github.com/Azure/azure-container-networking/cns/routes"
	acn "github.com/Azure/azure-container-networking/common"
	"github.com/Azure/azure-container-networking/ipam"
	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/network"
	"github.com/Azure/azure-container-networking/platform"
	"github.com/Azure/azure-container-networking/store"
)

const (
	// Key against which CNS state is persisted.
	storeKey        = "ContainerNetworkService"
	swiftAPIVersion = "1"
)

// httpRestService represents http listener for CNS - Container Networking Service.
type httpRestService struct {
	*cns.Service
	dockerClient     *dockerclient.DockerClient
	imdsClient       *imdsclient.ImdsClient
	ipamClient       *ipamclient.IpamClient
	networkContainer *networkcontainers.NetworkContainers
	routingTable     *routes.RoutingTable
	store            store.KeyValueStore
	state            *httpRestServiceState
	lock             sync.Mutex
	nm               network.NetworkManager
	am               ipam.AddressManager
}

// containerstatus is used to save status of an existing container
type containerstatus struct {
	ID                            string
	VMVersion                     string
	HostVersion                   string
	CreateNetworkContainerRequest cns.CreateNetworkContainerRequest
}

// httpRestServiceState contains the state we would like to persist.
type httpRestServiceState struct {
	Location        string
	NetworkType     string
	Initialized     bool
	ContainerStatus map[string]containerstatus
	Networks        map[string]*networkInfo
	TimeStamp       time.Time
}

type networkInfo struct {
	NetworkName string
	NicInfo     *imdsclient.InterfaceInfo
	Options     map[string]interface{}
}

// HTTPService describes the min API interface that every service should have.
type HTTPService interface {
	common.ServiceAPI
}

// NewHTTPRestService creates a new HTTP Service object.
func NewHTTPRestService(config *common.ServiceConfig) (HTTPService, error) {
	service, err := cns.NewService(config.Name, config.Version, config.Store)
	if err != nil {
		return nil, err
	}

	imdsClient := &imdsclient.ImdsClient{}
	routingTable := &routes.RoutingTable{}
	nc := &networkcontainers.NetworkContainers{}
	dc, err := dockerclient.NewDefaultDockerClient(imdsClient)

	if err != nil {
		return nil, err
	}

	ic, err := ipamclient.NewIpamClient("")
	if err != nil {
		return nil, err
	}

	serviceState := &httpRestServiceState{}
	serviceState.Networks = make(map[string]*networkInfo)

	// Setup network manager.
	netManager, err := network.NewNetworkManager()
	if err != nil {
		return nil, err
	}

	// Setup address manager.
	addrManager, err := ipam.NewAddressManager()
	if err != nil {
		return nil, err
	}

	return &httpRestService{
		Service:          service,
		store:            service.Service.Store,
		dockerClient:     dc,
		imdsClient:       imdsClient,
		ipamClient:       ic,
		networkContainer: nc,
		routingTable:     routingTable,
		state:            serviceState,
		nm:               netManager,
		am:               addrManager,
	}, nil

}

// Start starts the CNS listener.
func (service *httpRestService) Start(config *common.ServiceConfig) error {
	err := service.Initialize(config)
	if err != nil {
		log.Printf("[Azure CNS]  Failed to initialize base service, err:%v.", err)
		return err
	}

	if err = service.restoreState(); err != nil {
		log.Printf("[Azure CNS]  Failed to restore service state, err:%v.", err)
		return err
	}

	if err = service.restoreNetworkState(); err != nil {
		log.Printf("[Azure CNS]  Failed to restore network state, err:%v.", err)
		return err
	}

	var kvs store.KeyValueStore
	var storePath string
	if service.GetOption(acn.OptCnsUsePersistStore) == true {
		storePath = fmt.Sprintf("%vazure-vnet.json", platform.CNMRuntimePath)
	} else {
		storePath = fmt.Sprintf("%vazure-vnet.json", platform.CNIRuntimePath)
	}

	kvs, _ = store.NewJsonFileStore(storePath)

	// Initialize network manager
	if err = service.nm.Initialize(kvs); err != nil {
		log.Printf("[Azure CNS]  Failed to initialize network manager, err:%v.", err)
		return err
	} else if err = service.am.Initialize(service.nm, service.Options, kvs); err != nil {
		// Initialize address manager.
		log.Printf("[Azure CNS]  Failed to initialize IP address manager, err:%v.", err)
		return err
	}

	// Add handlers.
	listener := service.Listener
	// default handlers
	listener.AddHandler(cns.SetEnvironmentPath, service.setEnvironment)
	listener.AddHandler(cns.CreateNetworkPath, service.createNetwork)
	listener.AddHandler(cns.DeleteNetworkPath, service.deleteNetwork)
	listener.AddHandler(cns.ReserveIPAddressPath, service.reserveIPAddress)
	listener.AddHandler(cns.ReleaseIPAddressPath, service.releaseIPAddress)
	listener.AddHandler(cns.GetHostLocalIPPath, service.getHostLocalIP)
	listener.AddHandler(cns.GetIPAddressUtilizationPath, service.getIPAddressUtilization)
	listener.AddHandler(cns.GetUnhealthyIPAddressesPath, service.getUnhealthyIPAddresses)
	listener.AddHandler(cns.CreateOrUpdateNetworkContainer, service.createOrUpdateNetworkContainer)
	listener.AddHandler(cns.DeleteNetworkContainer, service.deleteNetworkContainer)
	listener.AddHandler(cns.GetNetworkContainerStatus, service.getNetworkContainerStatus)
	listener.AddHandler(cns.GetInterfaceForContainer, service.getInterfaceForContainer)
	listener.AddHandler(cns.GetNetworkInfoPath, service.getNetworkInfo)
	listener.AddHandler(cns.CreateNewNetworkPath, service.createNewNetwork)
	listener.AddHandler(cns.DeleteNewNetworkPath, service.deleteNewNetwork)
	listener.AddHandler(cns.CreateEndpointPath, service.createEndpoint)
	listener.AddHandler(cns.DeleteEndpointPath, service.deleteEndpoint)
	listener.AddHandler(cns.AttachEndpointPath, service.attachEndpoint)
	listener.AddHandler(cns.DetachEndpointPath, service.detachEndpoint)
	listener.AddHandler(cns.GetEndpointInfoPath, service.getEndpointInfo)
	listener.AddHandler(cns.AddExtIfRequestPath, service.addExtIf)
	listener.AddHandler(cns.StartSourcePath, service.startsource)
	listener.AddHandler(cns.GetDefaultAddressSpacesPath, service.getDefaultAddressSpaces)
	listener.AddHandler(cns.RequestPoolPath, service.requestPool)
	listener.AddHandler(cns.ReleasePoolPath, service.releasePool)
	listener.AddHandler(cns.GetPoolInfoPath, service.getPoolInfo)
	listener.AddHandler(cns.RequestAddressPath, service.requestAddress)
	listener.AddHandler(cns.ReleaseAddressPath, service.releaseAddress)
	listener.AddHandler(cns.SetPersistStoreUsagePath, service.setPersistStoreUsage)

	log.Printf("[Azure CNS]  Listening.")

	return nil
}

// Stop stops the CNS.
func (service *httpRestService) Stop() {
	service.am.Uninitialize()
	service.nm.Uninitialize()
	service.Uninitialize()
	log.Printf("[Azure CNS]  Service stopped.")
}

// Handles requests to set the environment type.
func (service *httpRestService) setEnvironment(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] setEnvironment")

	var req cns.SetEnvironmentRequest
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		log.Printf("[Azure CNS]  POST received for SetEnvironment.")
		service.state.Location = req.Location
		service.state.NetworkType = req.NetworkType
		service.state.Initialized = true
		service.saveState()
	default:
	}

	resp := &cns.Response{ReturnCode: 0}
	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handle getNetworkInfo requests from cns client
func (service *httpRestService) getNetworkInfo(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.GetNetworkInfoRequest
	nwInfo := &network.NetworkInfo{}

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		nwInfo, err = service.nm.GetNetworkInfo(req.NetworkName)
		if err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for GetNetworkInfo"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	nwInfoResp := &cns.GetNetworkInfoResponse{Response: resp, NwInfo: nwInfo}
	err = service.Listener.Encode(w, &nwInfoResp)
	log.Response(service.Name, nwInfoResp, err)
}

// Handle addExtIf requests from cns client
func (service *httpRestService) addExtIf(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.AddExtIfRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		if err = service.nm.AddExternalInterface(req.MasterIfName, req.SubnetPrefix); err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for AddExtIf"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handles createNewNetwork requests from cns client
func (service *httpRestService) createNewNetwork(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.CreateNewNetworkRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		if err = service.nm.CreateNetwork(req.NwInfo); err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for CreateNetwork"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handles deleteNewNetwork requests from cns client
func (service *httpRestService) deleteNewNetwork(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.DeleteNewNetworkRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		if err = service.nm.DeleteNetwork(req.NetworkName); err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for DeleteNetwork"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handles createEndpoint requests from cns client
func (service *httpRestService) createEndpoint(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.CreateEndpointRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		if err = service.nm.CreateEndpoint(req.NetworkName, req.EpInfo); err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for CreateEndpoint"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handles deleteEndpoint requests from cns client
func (service *httpRestService) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.DeleteEndpointRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		if err = service.nm.DeleteEndpoint(req.NetworkName, req.EndpointId); err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for DeleteEndpoint"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handles attachEndpoint requests from cns client
func (service *httpRestService) attachEndpoint(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.AttachEndpointRequest
	var epInfo *network.EndpointInfo

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		epInfo, err = service.nm.AttachEndpoint(req.NetworkName, req.EndpointId, req.SandboxKey)
		if err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for AttachEndpoint"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	epInfoResp := &cns.AttachEndpointResponse{Response: resp, EpInfo: epInfo}
	err = service.Listener.Encode(w, &epInfoResp)
	log.Response(service.Name, epInfoResp, err)
}

// Handles detachEndpoint requests from cns client
func (service *httpRestService) detachEndpoint(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.DetachEndpointRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		if err = service.nm.DetachEndpoint(req.NetworkName, req.EndpointId); err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for DetachEndpoint"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handles getEndpointInfo requests from cns client
func (service *httpRestService) getEndpointInfo(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.GetEndpointInfoRequest
	var epInfo *network.EndpointInfo

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		epInfo, err = service.nm.GetEndpointInfo(req.NetworkName, req.EndpointId)
		if err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for GetEndpointInfo"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	epInfoResp := &cns.GetEndpointInfoResponse{Response: resp, EpInfo: epInfo}
	err = service.Listener.Encode(w, &epInfoResp)
	log.Response(service.Name, epInfoResp, err)
}

// Handles startsource requests from cns client
func (service *httpRestService) startsource(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.StartSourceRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		if err = service.am.StartSource(req.Options); err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for StartSource"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handles getDefaultAddressSpaces requests from cns client
func (service *httpRestService) getDefaultAddressSpaces(w http.ResponseWriter, r *http.Request) {
	var err error
	returnCode := Success
	returnMessage := "Success"
	var localId string
	var globalId string

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		localId, globalId = service.am.GetDefaultAddressSpaces()
		if err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for GetDefaultAddressSpaces"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	respGetDefaultAddressSpaces := cns.GetDefaultAddressSpacesResponse{
		Response:                  resp,
		LocalDefaultAddressSpace:  localId,
		GlobalDefaultAddressSpace: globalId,
	}

	err = service.Listener.Encode(w, &respGetDefaultAddressSpaces)
	log.Response(service.Name, respGetDefaultAddressSpaces, err)
}

// Handles requestPool requests from cns client
func (service *httpRestService) requestPool(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.RequestPoolRequest
	var poolID string
	var subnet string

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		poolID, subnet, err = service.am.RequestPool(req.AsID, req.PoolID, req.SubPoolID, req.Options, req.V6)
		if err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for RequestPool"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	respRequestPool := cns.RequestPoolResponse{Response: resp, PoolID: poolID, Subnet: subnet}
	err = service.Listener.Encode(w, &respRequestPool)
	log.Response(service.Name, respRequestPool, err)
}

// Handles releasePool requests from cns client
func (service *httpRestService) releasePool(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.ReleasePoolRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		if err = service.am.ReleasePool(req.AsID, req.PoolID); err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for ReleasePool"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handles getPoolInfo requests from cns client
func (service *httpRestService) getPoolInfo(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.GetPoolInfoRequest
	var apInfo *ipam.AddressPoolInfo

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		apInfo, err = service.am.GetPoolInfo(req.AsID, req.PoolID)
		if err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for GetPoolInfo"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	respGetPoolInfo := cns.GetPoolInfoResponse{Response: resp, ApInfo: apInfo}
	err = service.Listener.Encode(w, &respGetPoolInfo)
	log.Response(service.Name, respGetPoolInfo, err)
}

// Handles requestAddress requests from cns client
func (service *httpRestService) requestAddress(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.RequestAddressRequest
	var address string

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		address, err = service.am.RequestAddress(req.AsID, req.PoolID, req.Address, req.Options)
		if err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for RequestAddress"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	respRequestAddress := cns.RequestAddressResponse{Response: resp, Address: address}
	err = service.Listener.Encode(w, &respRequestAddress)
	log.Response(service.Name, respRequestAddress, err)
}

// Handles releaseAddress requests from cns client
func (service *httpRestService) releaseAddress(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.ReleaseAddressRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		if err = service.am.ReleaseAddress(req.AsID, req.PoolID, req.Address, req.Options); err != nil {
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for ReleaseAddress"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handles setPersistStoreUsage call from cns client
func (service *httpRestService) setPersistStoreUsage(w http.ResponseWriter, r *http.Request) {
	returnCode := Success
	returnMessage := "Success"
	var req cns.SetPersistStoreUsageRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		var kvs store.KeyValueStore
		var storePath string
		if req.UsePersistStore == true {
			storePath = fmt.Sprintf("%vazure-vnet.json", platform.CNMRuntimePath)
		} else {
			storePath = fmt.Sprintf("%vazure-vnet.json", platform.CNIRuntimePath)
		}

		kvs, _ = store.NewJsonFileStore(storePath)
		if err = service.nm.SetStore(kvs); err != nil {
			log.Printf("[Azure CNS]  Failed to set store for network manager, err:%v.", err)
			returnCode = UnexpectedError
			returnMessage = err.Error()
		} else if err = service.am.SetStore(kvs); err != nil {
			log.Printf("[Azure CNS]  Failed to set store for IP address manager, err:%v.", err)
			returnCode = UnexpectedError
			returnMessage = err.Error()
		}
	default:
		returnCode = InvalidParameter
		returnMessage = "CNS service did not receive a POST for SetPersistStoreUsage"
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, err)
}

// Handles CreateNetwork requests.
func (service *httpRestService) createNetwork(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] createNetwork")

	var err error
	returnCode := 0
	returnMessage := ""

	if service.state.Initialized {
		var req cns.CreateNetworkRequest
		err = service.Listener.Decode(w, r, &req)
		log.Request(service.Name, &req, err)

		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. Unable to decode input request.")
			returnCode = InvalidParameter
		} else {
			switch r.Method {
			case "POST":
				dc := service.dockerClient
				rt := service.routingTable
				err = dc.NetworkExists(req.NetworkName)

				// Network does not exist.
				if err != nil {
					switch service.state.NetworkType {
					case "Underlay":
						switch service.state.Location {
						case "Azure":
							log.Printf("[Azure CNS] Goign to create network with name %v.", req.NetworkName)

							err = rt.GetRoutingTable()
							if err != nil {
								// We should not fail the call to create network for this.
								// This is because restoring routes is a fallback mechanism in case
								// network driver is not behaving as expected.
								// The responsibility to restore routes is with network driver.
								log.Printf("[Azure CNS] Unable to get routing table from node, %+v.", err.Error())
							}

							nicInfo, err := service.imdsClient.GetPrimaryInterfaceInfoFromHost()
							if err != nil {
								returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPrimaryInterfaceInfoFromHost failed %v.", err.Error())
								returnCode = UnexpectedError
								break
							}

							err = dc.CreateNetwork(req.NetworkName, nicInfo, req.Options)
							if err != nil {
								returnMessage = fmt.Sprintf("[Azure CNS] Error. CreateNetwork failed %v.", err.Error())
								returnCode = UnexpectedError
							}

							err = rt.RestoreRoutingTable()
							if err != nil {
								log.Printf("[Azure CNS] Unable to restore routing table on node, %+v.", err.Error())
							}

							networkInfo := &networkInfo{
								NetworkName: req.NetworkName,
								NicInfo:     nicInfo,
								Options:     req.Options,
							}

							service.state.Networks[req.NetworkName] = networkInfo

						case "StandAlone":
							returnMessage = fmt.Sprintf("[Azure CNS] Error. Underlay network is not supported in StandAlone environment. %v.", err.Error())
							returnCode = UnsupportedEnvironment
						}
					case "Overlay":
						returnMessage = fmt.Sprintf("[Azure CNS] Error. Overlay support not yet available. %v.", err.Error())
						returnCode = UnsupportedEnvironment
					}
				} else {
					returnMessage = fmt.Sprintf("[Azure CNS] Received a request to create an already existing network %v", req.NetworkName)
					log.Printf(returnMessage)
				}

			default:
				returnMessage = "[Azure CNS] Error. CreateNetwork did not receive a POST."
				returnCode = InvalidParameter
			}
		}

	} else {
		returnMessage = fmt.Sprintf("[Azure CNS] Error. CNS is not yet initialized with environment.")
		returnCode = UnsupportedEnvironment
	}

	resp := &cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)

	if returnCode == 0 {
		service.saveState()
	}

	log.Response(service.Name, resp, err)
}

// Handles DeleteNetwork requests.
func (service *httpRestService) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] deleteNetwork")

	var req cns.DeleteNetworkRequest
	returnCode := 0
	returnMessage := ""
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		dc := service.dockerClient
		err := dc.NetworkExists(req.NetworkName)

		// Network does exist
		if err == nil {
			log.Printf("[Azure CNS] Goign to delete network with name %v.", req.NetworkName)
			err := dc.DeleteNetwork(req.NetworkName)
			if err != nil {
				returnMessage = fmt.Sprintf("[Azure CNS] Error. DeleteNetwork failed %v.", err.Error())
				returnCode = UnexpectedError
			}
		} else {
			if err == fmt.Errorf("Network not found") {
				log.Printf("[Azure CNS] Received a request to delete network that does not exist: %v.", req.NetworkName)
			} else {
				returnCode = UnexpectedError
				returnMessage = err.Error()
			}
		}

	default:
		returnMessage = "[Azure CNS] Error. DeleteNetwork did not receive a POST."
		returnCode = InvalidParameter
	}

	resp := &cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)

	if returnCode == 0 {
		delete(service.state.Networks, req.NetworkName)
		service.saveState()
	}

	log.Response(service.Name, resp, err)
}

// Handles ip reservation requests.
func (service *httpRestService) reserveIPAddress(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] reserveIPAddress")

	var req cns.ReserveIPAddressRequest
	returnMessage := ""
	returnCode := 0
	addr := ""
	address := ""
	err := service.Listener.Decode(w, r, &req)

	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	if req.ReservationID == "" {
		returnCode = ReservationNotFound
		returnMessage = fmt.Sprintf("[Azure CNS] Error. ReservationId is empty")
	}

	switch r.Method {
	case "POST":
		ic := service.ipamClient

		ifInfo, err := service.imdsClient.GetPrimaryInterfaceInfoFromMemory()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPrimaryIfaceInfo failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		asID, err := ic.GetAddressSpace()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetAddressSpace failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		poolID, err := ic.GetPoolID(asID, ifInfo.Subnet)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPoolID failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		addr, err = ic.ReserveIPAddress(poolID, req.ReservationID)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] ReserveIpAddress failed with %+v", err.Error())
			returnCode = AddressUnavailable
			break
		}

		addressIP, _, err := net.ParseCIDR(addr)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] ParseCIDR failed with %+v", err.Error())
			returnCode = UnexpectedError
			break
		}
		address = addressIP.String()

	default:
		returnMessage = "[Azure CNS] Error. ReserveIP did not receive a POST."
		returnCode = InvalidParameter

	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}
	reserveResp := &cns.ReserveIPAddressResponse{Response: resp, IPAddress: address}
	err = service.Listener.Encode(w, &reserveResp)

	log.Response(service.Name, reserveResp, err)
}

// Handles release ip reservation requests.
func (service *httpRestService) releaseIPAddress(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] releaseIPAddress")

	var req cns.ReleaseIPAddressRequest
	returnMessage := ""
	returnCode := 0

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	if req.ReservationID == "" {
		returnCode = ReservationNotFound
		returnMessage = fmt.Sprintf("[Azure CNS] Error. ReservationId is empty")
	}

	switch r.Method {
	case "POST":
		ic := service.ipamClient

		ifInfo, err := service.imdsClient.GetPrimaryInterfaceInfoFromMemory()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPrimaryIfaceInfo failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		asID, err := ic.GetAddressSpace()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetAddressSpace failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		poolID, err := ic.GetPoolID(asID, ifInfo.Subnet)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPoolID failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		err = ic.ReleaseIPAddress(poolID, req.ReservationID)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] ReleaseIpAddress failed with %+v", err.Error())
			returnCode = ReservationNotFound
		}

	default:
		returnMessage = "[Azure CNS] Error. ReleaseIP did not receive a POST."
		returnCode = InvalidParameter
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)

	log.Response(service.Name, resp, err)
}

// Retrieves the host local ip address. Containers can talk to host using this IP address.
func (service *httpRestService) getHostLocalIP(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getHostLocalIP")
	log.Request(service.Name, "getHostLocalIP", nil)

	var found bool
	var errmsg string
	hostLocalIP := "0.0.0.0"

	if service.state.Initialized {
		switch r.Method {
		case "GET":
			switch service.state.NetworkType {
			case "Underlay":
				if service.imdsClient != nil {
					piface, err := service.imdsClient.GetPrimaryInterfaceInfoFromMemory()
					if err == nil {
						hostLocalIP = piface.PrimaryIP
						found = true
					} else {
						log.Printf("[Azure-CNS] Received error from GetPrimaryInterfaceInfoFromMemory. err: %v", err.Error())
					}
				}

			case "Overlay":
				errmsg = "[Azure-CNS] Overlay is not yet supported."
			}

		default:
			errmsg = "[Azure-CNS] GetHostLocalIP API expects a GET."
		}
	}

	returnCode := 0
	if !found {
		returnCode = NotFound
		if errmsg == "" {
			errmsg = "[Azure-CNS] Unable to get host local ip. Check if environment is initialized.."
		}
	}

	resp := cns.Response{ReturnCode: returnCode, Message: errmsg}
	hostLocalIPResponse := &cns.HostLocalIPAddressResponse{
		Response:  resp,
		IPAddress: hostLocalIP,
	}

	err := service.Listener.Encode(w, &hostLocalIPResponse)

	log.Response(service.Name, hostLocalIPResponse, err)
}

// Handles ip address utilization requests.
func (service *httpRestService) getIPAddressUtilization(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getIPAddressUtilization")
	log.Request(service.Name, "getIPAddressUtilization", nil)

	returnMessage := ""
	returnCode := 0
	capacity := 0
	available := 0
	var unhealthyAddrs []string

	switch r.Method {
	case "GET":
		ic := service.ipamClient

		ifInfo, err := service.imdsClient.GetPrimaryInterfaceInfoFromMemory()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPrimaryIfaceInfo failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		asID, err := ic.GetAddressSpace()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetAddressSpace failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		poolID, err := ic.GetPoolID(asID, ifInfo.Subnet)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPoolID failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		capacity, available, unhealthyAddrs, err = ic.GetIPAddressUtilization(poolID)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetIPUtilization failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}
		log.Printf("[Azure CNS] Capacity %v Available %v UnhealthyAddrs %v", capacity, available, unhealthyAddrs)

	default:
		returnMessage = "[Azure CNS] Error. GetIPUtilization did not receive a GET."
		returnCode = InvalidParameter
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	utilResponse := &cns.IPAddressesUtilizationResponse{
		Response:  resp,
		Available: available,
		Reserved:  capacity - available,
		Unhealthy: len(unhealthyAddrs),
	}

	err := service.Listener.Encode(w, &utilResponse)

	log.Response(service.Name, utilResponse, err)
}

// Handles retrieval of ip addresses that are available to be reserved from ipam driver.
func (service *httpRestService) getAvailableIPAddresses(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getAvailableIPAddresses")
	log.Request(service.Name, "getAvailableIPAddresses", nil)

	switch r.Method {
	case "GET":
	default:
	}

	resp := cns.Response{ReturnCode: 0}
	ipResp := &cns.GetIPAddressesResponse{Response: resp}
	err := service.Listener.Encode(w, &ipResp)

	log.Response(service.Name, ipResp, err)
}

// Handles retrieval of reserved ip addresses from ipam driver.
func (service *httpRestService) getReservedIPAddresses(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getReservedIPAddresses")
	log.Request(service.Name, "getReservedIPAddresses", nil)

	switch r.Method {
	case "GET":
	default:
	}

	resp := cns.Response{ReturnCode: 0}
	ipResp := &cns.GetIPAddressesResponse{Response: resp}
	err := service.Listener.Encode(w, &ipResp)

	log.Response(service.Name, ipResp, err)
}

// Handles retrieval of ghost ip addresses from ipam driver.
func (service *httpRestService) getUnhealthyIPAddresses(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getUnhealthyIPAddresses")
	log.Request(service.Name, "getUnhealthyIPAddresses", nil)

	returnMessage := ""
	returnCode := 0
	capacity := 0
	available := 0
	var unhealthyAddrs []string

	switch r.Method {
	case "GET":
		ic := service.ipamClient

		ifInfo, err := service.imdsClient.GetPrimaryInterfaceInfoFromMemory()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPrimaryIfaceInfo failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		asID, err := ic.GetAddressSpace()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetAddressSpace failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		poolID, err := ic.GetPoolID(asID, ifInfo.Subnet)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPoolID failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		capacity, available, unhealthyAddrs, err = ic.GetIPAddressUtilization(poolID)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetIPUtilization failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}
		log.Printf("[Azure CNS] Capacity %v Available %v UnhealthyAddrs %v", capacity, available, unhealthyAddrs)

	default:
		returnMessage = "[Azure CNS] Error. GetUnhealthyIP did not receive a POST."
		returnCode = InvalidParameter
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	ipResp := &cns.GetIPAddressesResponse{
		Response:    resp,
		IPAddresses: unhealthyAddrs,
	}

	err := service.Listener.Encode(w, &ipResp)

	log.Response(service.Name, ipResp, err)
}

// getAllIPAddresses retrieves all ip addresses from ipam driver.
func (service *httpRestService) getAllIPAddresses(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getAllIPAddresses")
	log.Request(service.Name, "getAllIPAddresses", nil)

	switch r.Method {
	case "GET":
	default:
	}

	resp := cns.Response{ReturnCode: 0}
	ipResp := &cns.GetIPAddressesResponse{Response: resp}
	err := service.Listener.Encode(w, &ipResp)

	log.Response(service.Name, ipResp, err)
}

// Handles health report requests.
func (service *httpRestService) getHealthReport(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getHealthReport")
	log.Request(service.Name, "getHealthReport", nil)

	switch r.Method {
	case "GET":
	default:
	}

	resp := &cns.Response{ReturnCode: 0}
	err := service.Listener.Encode(w, &resp)

	log.Response(service.Name, resp, err)
}

// saveState writes CNS state to persistent store.
func (service *httpRestService) saveState() error {
	log.Printf("[Azure CNS] saveState")

	// Skip if a store is not provided.
	if service.store == nil {
		log.Printf("[Azure CNS]  store not initialized.")
		return nil
	}

	// Update time stamp.
	service.state.TimeStamp = time.Now()
	err := service.store.Write(storeKey, &service.state)
	if err == nil {
		log.Printf("[Azure CNS]  State saved successfully.\n")
	} else {
		log.Printf("[Azure CNS]  Failed to save state., err:%v\n", err)
	}

	return err
}

// restoreState restores CNS state from persistent store.
func (service *httpRestService) restoreState() error {
	log.Printf("[Azure CNS] restoreState")

	// Skip if a store is not provided.
	if service.store == nil {
		log.Printf("[Azure CNS]  store not initialized.")
		return nil
	}

	// Read any persisted state.
	err := service.store.Read(storeKey, &service.state)
	if err != nil {
		if err == store.ErrKeyNotFound {
			// Nothing to restore.
			log.Printf("[Azure CNS]  No state to restore.\n")
			return nil
		}

		log.Printf("[Azure CNS]  Failed to restore state, err:%v\n", err)
		return err
	}

	log.Printf("[Azure CNS]  Restored state, %+v\n", service.state)
	return nil
}

func (service *httpRestService) createOrUpdateNetworkContainer(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] createOrUpdateNetworkContainer")

	var req cns.CreateNetworkContainerRequest

	returnMessage := ""
	returnCode := 0
	err := service.Listener.Decode(w, r, &req)

	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	if req.NetworkContainerid == "" {
		returnCode = NetworkContainerNotSpecified
		returnMessage = fmt.Sprintf("[Azure CNS] Error. NetworkContainerid is empty")
	}

	switch r.Method {
	case "POST":
		nc := service.networkContainer
		err := nc.Create(req)

		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. CreateOrUpdateNetworkContainer failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		// we don't want to overwrite what other calls may have written
		service.lock.Lock()
		defer service.lock.Unlock()

		existing, ok := service.state.ContainerStatus[req.NetworkContainerid]
		var hostVersion string
		if ok {
			hostVersion = existing.HostVersion
		}

		if service.state.ContainerStatus == nil {
			service.state.ContainerStatus = make(map[string]containerstatus)
		}

		service.state.ContainerStatus[req.NetworkContainerid] =
			containerstatus{
				ID:                            req.NetworkContainerid,
				VMVersion:                     req.Version,
				CreateNetworkContainerRequest: req,
				HostVersion:                   hostVersion}
		service.saveState()

	default:
		returnMessage = "[Azure CNS] Error. CreateOrUpdateNetworkContainer did not receive a POST."
		returnCode = InvalidParameter

	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	reserveResp := &cns.CreateNetworkContainerResponse{Response: resp}
	err = service.Listener.Encode(w, &reserveResp)

	log.Response(service.Name, reserveResp, err)
}

func (service *httpRestService) getNetworkContainer(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getNetworkContainer")

	var req cns.GetNetworkContainerRequest

	returnMessage := ""
	returnCode := 0
	err := service.Listener.Decode(w, r, &req)

	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	reserveResp := &cns.GetNetworkContainerResponse{Response: resp}
	err = service.Listener.Encode(w, &reserveResp)

	log.Response(service.Name, reserveResp, err)

}

func (service *httpRestService) deleteNetworkContainer(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] deleteNetworkContainer")

	var req cns.DeleteNetworkContainerRequest

	returnMessage := ""
	returnCode := 0
	err := service.Listener.Decode(w, r, &req)

	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	if req.NetworkContainerid == "" {
		returnCode = NetworkContainerNotSpecified
		returnMessage = fmt.Sprintf("[Azure CNS] Error. NetworkContainerid is empty")
	}

	switch r.Method {
	case "POST":
		nc := service.networkContainer
		err := nc.Delete(req.NetworkContainerid)

		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. DeleteNetworkContainer failed %v", err.Error())
			returnCode = UnexpectedError
			break
		} else {
			service.lock.Lock()
			if service.state.ContainerStatus != nil {
				delete(service.state.ContainerStatus, req.NetworkContainerid)
			}
			service.lock.Unlock()
		}
		break
	default:
		returnMessage = "[Azure CNS] Error. DeleteNetworkContainer did not receive a POST."
		returnCode = InvalidParameter
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	reserveResp := &cns.DeleteNetworkContainerResponse{Response: resp}
	err = service.Listener.Encode(w, &reserveResp)

	log.Response(service.Name, reserveResp, err)
}

func (service *httpRestService) getNetworkContainerStatus(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getNetworkContainerStatus")

	var req cns.GetNetworkContainerStatusRequest
	returnMessage := ""
	returnCode := 0
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	service.lock.Lock()
	defer service.lock.Unlock()
	var ok bool
	var containerDetails containerstatus

	containerInfo := service.state.ContainerStatus
	if containerInfo != nil {
		containerDetails, ok = containerInfo[req.NetworkContainerid]
	} else {
		ok = false
	}

	var hostVersion string
	var vmVersion string

	if ok {
		savedReq := containerDetails.CreateNetworkContainerRequest
		containerVersion, err := service.imdsClient.GetNetworkContainerInfoFromHost(
			req.NetworkContainerid,
			savedReq.PrimaryInterfaceIdentifier,
			savedReq.AuthorizationToken, swiftAPIVersion)

		if err != nil {
			returnCode = CallToHostFailed
			returnMessage = err.Error()
		} else {
			hostVersion = containerVersion.ProgrammedVersion
		}
	} else {
		returnMessage = "[Azure CNS] Never received call to create this container."
		returnCode = UnknownContainerID
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	networkContainerStatusReponse := cns.GetNetworkContainerStatusResponse{
		Response:           resp,
		NetworkContainerid: req.NetworkContainerid,
		AzureHostVersion:   hostVersion,
		Version:            vmVersion,
	}

	err = service.Listener.Encode(w, &networkContainerStatusReponse)

	log.Response(service.Name, networkContainerStatusReponse, err)
}

func (service *httpRestService) getInterfaceForContainer(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getInterfaceForContainer")

	var req cns.GetInterfaceForContainerRequest
	returnMessage := ""
	returnCode := 0
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	containerInfo := service.state.ContainerStatus
	containerDetails, ok := containerInfo[req.NetworkContainerID]
	var interfaceName string
	var ipaddress string
	var vnetSpace []cns.IPSubnet

	if ok {
		savedReq := containerDetails.CreateNetworkContainerRequest
		interfaceName = savedReq.NetworkContainerid
		vnetSpace = savedReq.VnetAddressSpace
		ipaddress = savedReq.IPConfiguration.IPSubnet.IPAddress // it has to exist
	} else {
		returnMessage = "[Azure CNS] Never received call to create this container."
		returnCode = UnknownContainerID
		interfaceName = ""
		ipaddress = ""
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	getInterfaceForContainerResponse := cns.GetInterfaceForContainerResponse{
		Response:         resp,
		NetworkInterface: cns.NetworkInterface{Name: interfaceName, IPAddress: ipaddress},
		VnetAddressSpace: vnetSpace,
	}

	err = service.Listener.Encode(w, &getInterfaceForContainerResponse)

	log.Response(service.Name, getInterfaceForContainerResponse, err)
}

// restoreNetworkState restores Network state that existed before reboot.
func (service *httpRestService) restoreNetworkState() error {
	log.Printf("[Azure CNS] Enter Restoring Network State")

	if service.store == nil {
		log.Printf("[Azure CNS] Store is not initialized, nothing to restore for network state.")
		return nil
	}

	rebooted := false
	modTime, err := service.store.GetModificationTime()

	if err == nil {
		log.Printf("[Azure CNS] Store timestamp is %v.", modTime)

		rebootTime, err := platform.GetLastRebootTime()
		if err == nil && rebootTime.After(modTime) {
			log.Printf("[Azure CNS] reboot time %v mod time %v", rebootTime, modTime)
			rebooted = true
		}
	}

	if rebooted {
		for _, nwInfo := range service.state.Networks {
			enableSnat := true

			log.Printf("[Azure CNS] Restore nwinfo %v", nwInfo)

			if nwInfo.Options != nil {
				if _, ok := nwInfo.Options[dockerclient.OptDisableSnat]; ok {
					enableSnat = false
				}
			}

			if enableSnat {
				err := common.SetOutboundSNAT(nwInfo.NicInfo.Subnet)
				if err != nil {
					log.Printf("[Azure CNS] Error setting up SNAT outbound rule %v", err)
					return err
				}
			}
		}
	}

	return nil
}
