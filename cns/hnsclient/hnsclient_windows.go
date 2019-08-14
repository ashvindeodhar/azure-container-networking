package hnsclient

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/common"
	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/platform"
	"github.com/Microsoft/hcsshim"
)

const (
	// Name of the external hns network
	ExtHnsNetworkName = "ext"

	// Address prefix for external hns network
	ExtHnsNetworkAddressPrefix = "192.168.255.0/30"

	// Gateway address for external hns network
	ExtHnsNetworkGwAddress = "192.168.255.1"

	// HNS network types
	hnsL2Bridge = "l2bridge"
	hnsL2Tunnel = "l2tunnel"

	// Name of the executable to manage windows network compartment
	// creation and deletion
	compartmentManagementBinary = "CNS-CompartmentManagement.exe"

	// Azure DNS IP
	AzureDNS = "168.63.129.16"

	// Default network compartment ID
	DefaultNetworkCompartmentID = 1

	// Maximum number of Network containers allowed in the network compartment
	MaxNCsPerCompartment = 2

	// Multitenancy encap type
	encapTypeVLAN = "VLAN"

	// Network adapter prefix
	networkAdapterPrefix = "vEthernet"
)

var (
	// Named Lock for network and endpoint creation/deletion
	namedLock = common.InitNamedLock()
)

// CreateHnsNetwork creates the HNS network with the provided configuration
func CreateHnsNetwork(nwConfig cns.CreateHnsNetworkRequest) error {
	log.Printf("[Azure CNS] CreateHnsNetwork")
	// Initialize HNS network.
	hnsNetwork := &hcsshim.HNSNetwork{
		Name:                 nwConfig.NetworkName,
		Type:                 nwConfig.NetworkType,
		NetworkAdapterName:   nwConfig.NetworkAdapterName,
		SourceMac:            nwConfig.SourceMac,
		DNSSuffix:            nwConfig.DNSSuffix,
		DNSServerList:        nwConfig.DNSServerList,
		DNSServerCompartment: nwConfig.DNSServerCompartment,
		ManagementIP:         nwConfig.ManagementIP,
		AutomaticDNS:         nwConfig.AutomaticDNS,
	}

	for _, policy := range nwConfig.Policies {
		hnsNetwork.Policies = append(hnsNetwork.Policies, policy)
	}

	for _, subnet := range nwConfig.Subnets {
		hnsSubnet := hcsshim.Subnet{
			AddressPrefix:  subnet.AddressPrefix,
			GatewayAddress: subnet.GatewayAddress,
		}

		hnsNetwork.Subnets = append(hnsNetwork.Subnets, hnsSubnet)
	}

	for _, macPool := range nwConfig.MacPools {
		hnsMacPool := hcsshim.MacPool{
			StartMacAddress: macPool.StartMacAddress,
			EndMacAddress:   macPool.EndMacAddress,
		}
		hnsNetwork.MacPools = append(hnsNetwork.MacPools, hnsMacPool)
	}

	namedLock.LockAcquire(hnsNetwork.Name)
	defer namedLock.LockRelease(hnsNetwork.Name)

	return createHnsNetwork(hnsNetwork)
}

// DeleteHnsNetwork deletes the HNS network with the provided name
func DeleteHnsNetwork(networkName string) error {
	log.Printf("[Azure CNS] DeleteHnsNetwork")

	namedLock.LockAcquire(networkName)
	defer namedLock.LockRelease(networkName)

	return deleteHnsNetwork(networkName)
}

// CreateDefaultExtNetwork creates default HNS network named ext (if it doesn't exist already)
// to create external switch on windows platform.
// This allows orchestrators to start CNS which pre-provisions the network so that the
// VM network blip / disconnect is avoided when calling cni add for the very first time.
func CreateDefaultExtNetwork(networkType string) error {
	networkType = strings.ToLower(strings.TrimSpace(networkType))
	if len(networkType) == 0 {
		return nil
	}

	if networkType != hnsL2Bridge && networkType != hnsL2Tunnel {
		return fmt.Errorf("Invalid hns network type %s", networkType)
	}

	namedLock.LockAcquire(ExtHnsNetworkName)
	defer namedLock.LockRelease(ExtHnsNetworkName)

	log.Printf("[Azure CNS] CreateDefaultExtNetwork")
	extHnsNetwork, _ := hcsshim.GetHNSNetworkByName(ExtHnsNetworkName)

	if extHnsNetwork != nil {
		log.Printf("[Azure CNS] Found existing DefaultExtNetwork with type: %s", extHnsNetwork.Type)
		if !strings.EqualFold(networkType, extHnsNetwork.Type) {
			return fmt.Errorf("Network type mismatch with existing network: %s", extHnsNetwork.Type)
		}

		return nil
	}

	// create new hns network
	log.Printf("[Azure CNS] Creating DefaultExtNetwork with type %s", networkType)

	hnsNetwork := &hcsshim.HNSNetwork{
		Name: ExtHnsNetworkName,
		Type: networkType,
	}

	hnsSubnet := hcsshim.Subnet{
		AddressPrefix:  ExtHnsNetworkAddressPrefix,
		GatewayAddress: ExtHnsNetworkGwAddress,
	}

	hnsNetwork.Subnets = append(hnsNetwork.Subnets, hnsSubnet)

	return createHnsNetwork(hnsNetwork)
}

// DeleteDefaultExtNetwork deletes the default HNS network
func DeleteDefaultExtNetwork() error {
	log.Printf("[Azure CNS] DeleteDefaultExtNetwork")

	namedLock.LockAcquire(ExtHnsNetworkName)
	defer namedLock.LockRelease(ExtHnsNetworkName)

	return deleteHnsNetwork(ExtHnsNetworkName)
}

// createHnsNetwork calls the hcshim to create the hns network
func createHnsNetwork(hnsNetwork *hcsshim.HNSNetwork) error {
	// Marshal the request.
	buffer, err := json.Marshal(hnsNetwork)
	if err != nil {
		return err
	}
	hnsRequest := string(buffer)

	// Create HNS network.
	log.Printf("[Azure CNS] Creating HNS network: %+v", hnsRequest)
	if _, err := hcsshim.HNSNetworkRequest("POST", "", hnsRequest); err != nil {
		return fmt.Errorf("ERROR: Failed to create network due to error: %v", err)
	}

	return nil
}

// deleteHnsNetwork calls HNS to delete the network with the provided name
func deleteHnsNetwork(networkName string) error {
	network, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		// If error is anything other than networkNotFound return error
		if _, networkNotFound := err.(hcsshim.NetworkNotFoundError); !networkNotFound {
			return fmt.Errorf("[Azure CNS] ERROR: Failed GetHNSNetworkByName due to error: %v", err)
		}

		log.Errorf("[Azure CNS] Network: %s not found for deletion", networkName)

		return nil
	}

	// Delete HNS network.
	log.Printf("[Azure CNS] Deleting HNS network: %+v", network)
	if _, err = hcsshim.HNSNetworkRequest("DELETE", network.Id, ""); err != nil {
		return fmt.Errorf("ERROR: Failed to delete network: %s due to error: %v",
			networkName, err)
	}

	return nil
}

// CreateCompartment creates windows network compartment
func CreateCompartment() (int, error) {
	log.Printf("[Azure CNS] CreateCompartment")

	var (
		err           error
		compartmentID int
		stdout        string
	)

	if _, err = os.Stat(compartmentManagementBinary); err != nil {
		log.Errorf("[Azure CNS] ERROR: Unable to find %s needed for compartment creation",
			compartmentManagementBinary)
		return compartmentID, fmt.Errorf("ERROR: Unable to create the compartment")
	}

	args := compartmentManagementBinary + " /operation create"
	log.Printf("[Azure CNS] Creating compartment: %v", args)

	if stdout, err = platform.ExecuteCommand(args); err != nil {
		log.Errorf("[Azure CNS] ERROR: Failed to create compartment due to error: %v", err)
		return compartmentID, fmt.Errorf("ERROR: Failed to create compartment due to error: %v", err)
	}

	if compartmentID, err = strconv.Atoi(strings.TrimSpace(stdout)); err != nil {
		log.Errorf("[Azure CNS] Unable to parse output from %s", compartmentManagementBinary)
		return compartmentID, fmt.Errorf("ERROR: Failed to create compartment due to error: %v", err)
	}

	log.Printf("[Azure CNS] Successfully created compartment with ID: %d", compartmentID)

	return compartmentID, nil
}

// DeleteCompartment deletes windows network compartment
func DeleteCompartment(compartmentID int) error {
	log.Printf("[Azure CNS] DeleteCompartment")

	var (
		err error
	)

	if _, err = os.Stat(compartmentManagementBinary); err != nil {
		log.Errorf("[Azure CNS] ERROR: Unable to find %s needed for compartment deletion",
			compartmentManagementBinary)
		return fmt.Errorf("ERROR: Unable to delete the compartment")
	}

	args := compartmentManagementBinary + " /operation delete " + strconv.Itoa(compartmentID)
	log.Printf("[Azure CNS] Deleting compartment: %v", args)

	if _, err = platform.ExecuteCommand(args); err != nil {
		log.Errorf("[Azure CNS] ERROR: Failed to delete compartment due to error: %v", err)
		return fmt.Errorf("ERROR: Failed to delete compartment due to error: %v", err)
	}

	log.Printf("[Azure CNS] Successfully deleted network compartment with ID: %d", compartmentID)

	return nil
}

// CleanupEndpoint detaches endpoint from the host and deletes it
func CleanupEndpoint(endpointName string) error {
	log.Printf("[Azure CNS] CleanupEndpoint")

	namedLock.LockAcquire(endpointName)
	defer namedLock.LockRelease(endpointName)

	endpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err != nil {
		// If error is anything other than endpointNotFound return error
		if _, endpointNotFound := err.(hcsshim.EndpointNotFoundError); !endpointNotFound {
			return fmt.Errorf("ERROR: Unable to retrieve endpoint for deletion")
		}

		// If the endpoint is not found continue to delete the next endpoint
		log.Printf("[Azure CNS] ERROR: Unable to find endpoint: %s for deletion", endpointName)
		return nil
	}

	// Detach endpoint from the compartment
	log.Printf("[Azure CNS] Detaching HNS endpoint: %+v", endpoint)
	if err = endpoint.HostDetach(); err != nil {
		return fmt.Errorf("ERROR: Failed to detach endpoint: %v due to error: %v", endpoint, err)
	}

	log.Printf("[Azure CNS] Successfully detached endpoint: %s", endpointName)

	// Delete HNS endpoint
	return deleteEndpoint(endpoint)
}

// deleteEndpoint deletes endpoint
func deleteEndpoint(endpoint *hcsshim.HNSEndpoint) error {
	log.Printf("[Azure CNS] Deleting HNS endpoint: %+v", endpoint)
	if _, err := hcsshim.HNSEndpointRequest("DELETE", endpoint.Id, ""); err != nil {
		log.Errorf("[Azure CNS] ERROR: Failed to delete endpoint: %v due to error: %v", endpoint, err)
		return fmt.Errorf("ERROR: Failed to delete endpoint: %v due to error: %v", endpoint, err)
	}

	log.Printf("[Azure CNS] Successfully deleted endpoint: %s", endpoint.Name)

	return nil
}

// SetupNetworkAndEndpoints sets up network and endpoint for the specified network
// container and windows network compartment ID
func SetupNetworkAndEndpoints(
	networkContainerInfo *cns.GetNetworkContainerResponse, ncID string, compartmentID int) error {
	log.Printf("[Azure CNS] SetupNetworkAndEndpoints")
	var (
		err          error
		network      *hcsshim.HNSNetwork
		endpoint     *hcsshim.HNSEndpoint
		endpointName = ncID
	)

	if network, err = createNetworkWithNC(networkContainerInfo); err != nil {
		return err
	}

	namedLock.LockAcquire(endpointName)
	defer namedLock.LockRelease(endpointName)

	if endpoint, err = createEndpointWithNC(networkContainerInfo, ncID, network.Id); err != nil {
		return err
	}

	if err = attachEndpointToCompartment(endpoint, compartmentID); err != nil {
		deleteEndpoint(endpoint)
		return err
	}

	return nil
}

// Get the network adapter name for the specified NC
func GetNetworkAdapterNameForNC(networkContainerInfo *cns.GetNetworkContainerResponse) (string, error) {
	var (
		err                   error
		networkAdapterName    string
		interfaceSubnetPrefix *net.IPNet
	)
	log.Printf("[Azure CNS] Primary interface identifier IP: %s", networkContainerInfo.PrimaryInterfaceIdentifier)

	interfaceSubnetPrefix = common.GetInterfaceSubnetWithSpecificIp(networkContainerInfo.PrimaryInterfaceIdentifier)
	if interfaceSubnetPrefix == nil {
		err = fmt.Errorf("[Azure CNS] Interface not found for primary interface identifier IP: %s",
			networkContainerInfo.PrimaryInterfaceIdentifier)
		log.Errorf(err.Error())
		return "", err
	}

	interfaceSubnetPrefix.IP = interfaceSubnetPrefix.IP.Mask(interfaceSubnetPrefix.Mask)

	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			_, ipnet, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if interfaceSubnetPrefix.String() == ipnet.String() {
				networkAdapterName = iface.Name
				break
			}
		}
	}

	if strings.TrimSpace(networkAdapterName) == "" {
		err = fmt.Errorf("[Azure CNS] Failed to get networkAdapterName: %s for primary interface identifier: %s",
			networkAdapterName, networkContainerInfo.PrimaryInterfaceIdentifier)
		log.Errorf(err.Error())
		return "", err
	}

	// FixMe: Find a better way to check if a nic that is selected is not part of a vSwitch
	if strings.HasPrefix(networkAdapterName, networkAdapterPrefix) {
		networkAdapterName = ""
	}

	return networkAdapterName, nil
}

// Get the network name for the specified NC
func GetNetworkNameForNC(networkContainerInfo *cns.GetNetworkContainerResponse) (string, error) {
	if !strings.EqualFold(networkContainerInfo.MultiTenancyInfo.EncapType, encapTypeVLAN) {
		return "", fmt.Errorf("Invalid multitenancy Encap type: %s. Expecting %s",
			networkContainerInfo.MultiTenancyInfo.EncapType, encapTypeVLAN)
	}

	if networkContainerInfo.MultiTenancyInfo.ID == 0 {
		return "", fmt.Errorf("Invalid multitenancy VLAN ID: %d", networkContainerInfo.MultiTenancyInfo.ID)
	}

	// network name is of the format azure-vlan1-192-168-0-0_24
	subnet := net.ParseIP(networkContainerInfo.IPConfiguration.IPSubnet.IPAddress)
	subnet = subnet.Mask(net.CIDRMask(int(networkContainerInfo.IPConfiguration.IPSubnet.PrefixLength), 32))
	networkName := strings.Replace(subnet.String(), ".", "-", -1)
	networkName += "_" + strconv.Itoa(int(networkContainerInfo.IPConfiguration.IPSubnet.PrefixLength))
	networkName = fmt.Sprintf("azure-vlan%v-%v", networkContainerInfo.MultiTenancyInfo.ID, networkName)
	return networkName, nil
}

// Create network to hold the endpoint for the specified NC
func createNetworkWithNC(
	networkContainerInfo *cns.GetNetworkContainerResponse) (*hcsshim.HNSNetwork, error) {
	var (
		err                error
		networkName        string
		networkAdapterName string
		network            *hcsshim.HNSNetwork
		subnetPrefix       net.IPNet
	)

	// validate the multitenancy info
	if !strings.EqualFold(networkContainerInfo.MultiTenancyInfo.EncapType, encapTypeVLAN) {
		return nil, fmt.Errorf("Invalid multitenancy Encap type: %s. Expecting %s",
			networkContainerInfo.MultiTenancyInfo.EncapType, encapTypeVLAN)
	}

	if networkContainerInfo.MultiTenancyInfo.ID == 0 {
		return nil, fmt.Errorf("Invalid multitenancy VLAN ID: %d", networkContainerInfo.MultiTenancyInfo.ID)
	}

	ipAddress := net.ParseIP(networkContainerInfo.IPConfiguration.IPSubnet.IPAddress)
	if ipAddress.To4() != nil {
		subnetPrefix = net.IPNet{
			IP:   ipAddress,
			Mask: net.CIDRMask(int(networkContainerInfo.IPConfiguration.IPSubnet.PrefixLength), 32)}
	} else {
		subnetPrefix = net.IPNet{
			IP:   ipAddress,
			Mask: net.CIDRMask(int(networkContainerInfo.IPConfiguration.IPSubnet.PrefixLength), 128)}
	}

	subnetPrefix.IP = subnetPrefix.IP.Mask(subnetPrefix.Mask)

	if networkName, err = GetNetworkNameForNC(networkContainerInfo); err != nil {
		return nil, fmt.Errorf("[Azure CNS] ERROR: Failed to get network name due to error: %v", err)
	}

	namedLock.LockAcquire(networkName)
	defer namedLock.LockRelease(networkName)

	// Check if the network already exists
	if network, err = hcsshim.GetHNSNetworkByName(networkName); err != nil {
		// If error is anything other than networkNotFound return error
		if _, networkNotFound := err.(hcsshim.NetworkNotFoundError); !networkNotFound {
			return nil, fmt.Errorf("[Azure CNS] ERROR: Failed GetHNSNetworkByName due to error: %v", err)
		}

		// Get network adapter name
		if networkAdapterName, err = GetNetworkAdapterNameForNC(networkContainerInfo); err != nil {
			log.Errorf("[Azure CNS] Failed to get network adapter name due to error: %v", err)
			return nil, fmt.Errorf("Failed to get network adapter name due to error: %v", err)
		}

		// Create the network.
		log.Printf("[Azure CNS] Creating network %s", networkName)
		dnsServerList := strings.Join(networkContainerInfo.IPConfiguration.DNSServers, ", ")
		dnsServerList += ", " + AzureDNS

		network = &hcsshim.HNSNetwork{
			Name:               networkName,
			NetworkAdapterName: networkAdapterName,
			DNSServerList:      dnsServerList,
			Type:               hnsL2Bridge,
		}

		// Set the network VLAN policy
		vlanPolicy := hcsshim.VlanPolicy{
			Type: encapTypeVLAN,
		}
		vlanPolicy.VLAN = uint(networkContainerInfo.MultiTenancyInfo.ID)
		serializedVlanPolicy, _ := json.Marshal(vlanPolicy)
		network.Policies = append(network.Policies, serializedVlanPolicy)

		// Populate subnet
		subnet := hcsshim.Subnet{
			AddressPrefix:  subnetPrefix.String(),
			GatewayAddress: networkContainerInfo.IPConfiguration.GatewayIPAddress,
		}
		network.Subnets = append(network.Subnets, subnet)

		createNetworkRequest, err := json.Marshal(network)
		if err != nil {
			return nil, fmt.Errorf("[Azure CNS] Failed to marshal network %s due to error: %v",
				networkName, err)
		}

		// Create HNS network.
		log.Printf("[Azure CNS] Creating HNS network: %+v", string(createNetworkRequest))
		if network, err = hcsshim.HNSNetworkRequest("POST", "", string(createNetworkRequest)); err != nil {
			log.Errorf("[Azure CNS] Failed to create the network: %s due to error: %v", networkName, err)
			return nil, fmt.Errorf("[Azure CNS] Failed to create HNS network: %s due to error: %v", networkName, err)
		}

		log.Printf("[Azure CNS] Successfully created network: %+v", network)
	} else {
		log.Printf("[Azure CNS] Network is already present. Network: %+v", network)
	}

	return network, nil
}

// Create endpoint for the specified NC
func createEndpointWithNC(
	networkContainerInfo *cns.GetNetworkContainerResponse,
	ncID string,
	networkID string) (*hcsshim.HNSEndpoint, error) {
	var (
		err          error
		endpoint     *hcsshim.HNSEndpoint
		endpointName = ncID
	)

	// Check if the endpoint already exists
	if endpoint, err = hcsshim.GetHNSEndpointByName(endpointName); err != nil {
		// If error is anything other than endpointNotFound return error
		if _, endpointNotFound := err.(hcsshim.EndpointNotFoundError); !endpointNotFound {
			return nil, fmt.Errorf("[Azure CNS] ERROR: Failed GetHNSEndpointByName due to error: %v", err)
		}

		var jsonPolicies []json.RawMessage
		outBoundNatPolicy := hcsshim.OutboundNatPolicy{}
		outBoundNatPolicy.Policy.Type = hcsshim.OutboundNat
		for _, ipAddress := range networkContainerInfo.CnetAddressSpace {
			outBoundNatPolicy.Exceptions = append(outBoundNatPolicy.Exceptions,
				ipAddress.IPAddress+"/"+strconv.Itoa(int(ipAddress.PrefixLength)))
		}

		if outBoundNatPolicy.Exceptions != nil {
			serializedOutboundNatPolicy, _ := json.Marshal(outBoundNatPolicy)
			jsonPolicies = append(jsonPolicies, serializedOutboundNatPolicy)
		}

		dnsServerList := strings.Join(networkContainerInfo.IPConfiguration.DNSServers, ", ")
		dnsServerList += ", " + AzureDNS
		endpoint = &hcsshim.HNSEndpoint{
			Name:           endpointName,
			IPAddress:      net.ParseIP(networkContainerInfo.IPConfiguration.IPSubnet.IPAddress),
			VirtualNetwork: networkID,
			DNSServerList:  dnsServerList,
			Policies:       jsonPolicies,
		}

		createEndpointRequest, err := json.Marshal(endpoint)
		if err != nil {
			return nil, fmt.Errorf("[Azure CNS] Failed to marshal endpoint %s err:%v", endpointName, err)
		}

		// Create HNS endpoint.
		log.Printf("[Azure CNS] Creating HNS endpoint: %+v", string(createEndpointRequest))
		if endpoint, err = hcsshim.HNSEndpointRequest("POST", "", string(createEndpointRequest)); err != nil {
			log.Printf("[Azure CNS] ERROR: Failed to create endpoint: %s due to error: %v", endpointName, err)
			return nil, fmt.Errorf("[Azure CNS] Failed to create HNS endpoint: %s error: %v", endpointName, err)
		}

		log.Printf("[Azure CNS] Successfully created endpoint: %+v", endpoint)
	} else {
		log.Printf("[Azure CNS] ERROR: Endpoint is already present. Endpoint: %+v", endpoint)
		return nil, fmt.Errorf("[Azure CNS] ERROR: Endpoint: %s already present.", endpointName)
	}

	return endpoint, nil
}

// Attach endpoint to the given compartment
func attachEndpointToCompartment(endpoint *hcsshim.HNSEndpoint, compartmentID int) error {
	if err := endpoint.HostAttach(uint16(compartmentID)); err != nil {
		return fmt.Errorf("[Azure CNS] Failed to attach endpoint: %s to compartment with ID: %d due to error: %+v",
			endpoint.Name, compartmentID, err)
	}

	log.Printf("[Azure CNS] Successfully attached endpoint: %s to compartment with ID: %d", endpoint.Name, compartmentID)

	return nil
}

// IsCompartmentManagementSupported validates if the compartment management feature can be supported
func IsCompartmentManagementSupported() error {
	log.Printf("[Azure CNS] IsCompartmentManagementSupported")

	if _, err := os.Stat(compartmentManagementBinary); err != nil {
		errMsg := fmt.Sprintf("ERROR: Unable to find %s needed for compartment creation", compartmentManagementBinary)
		log.Errorf("[Azure CNS] %s", errMsg)
		return fmt.Errorf(errMsg)
	}

	args := compartmentManagementBinary + " /operation validate"
	log.Printf("[Azure CNS] Checking if compartment management is supported: %v", args)

	if _, err := platform.ExecuteCommand(args); err != nil {
		errMsg := fmt.Sprintf("ERROR: Compartment management is not supported due to error: %v", err)
		log.Errorf("[Azure CNS] %s", errMsg)
		return fmt.Errorf(errMsg)
	}

	log.Printf("[Azure CNS] Compartment management is supported")

	return nil
}
