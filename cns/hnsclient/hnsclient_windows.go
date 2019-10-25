package hnsclient

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/networkcontainers"
	"github.com/Azure/azure-container-networking/common"
	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/network/policy"
	"github.com/Azure/azure-container-networking/platform"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
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
	compartmentManagementBinary = "azure-cns-compartmentmanagement.exe"

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
	// hcnSchemaVersionMajor indicates major version number for hcn schema
	hcnSchemaVersionMajor = 2

	// hcnSchemaVersionMinor indicates minor version number for hcn schema
	hcnSchemaVersionMinor = 0

	// hcnIpamTypeStatic indicates the static type of ipam
	hcnIpamTypeStatic = "Static"

	// hostNCApipaNetworkName indicates the name of the apipa network used for host container connectivity
	hostNCApipaNetworkName = "HostNCApipaNetwork"

	// hostNCApipaNetworkType indicates the type of hns network set up for host NC connectivity
	hostNCApipaNetworkType = hcn.L2Bridge

	// hostNCApipaEndpointName indicates the prefix for the name of the apipa endpoint used for
	// the host container connectivity
	hostNCApipaEndpointNamePrefix = "HostNCApipaEndpoint"

	// Name of the loopback adapter needed to create Host NC apipa network
	hostNCLoopbackAdapterName = "LoopbackAdapterHostNCConnectivity"

	// protocolTCP indicates the TCP protocol identifier in HCN
	protocolTCP = "6"

	// protocolUDP indicates the UDP protocol identifier in HCN
	protocolUDP = "17"

	// protocolICMPv4 indicates the ICMPv4 protocol identifier in HCN
	protocolICMPv4 = "1"

	// aclPriority2000 indicates the ACL priority of 2000
	aclPriority2000 = 2000

	// aclPriority200 indicates the ACL priority of 200
	aclPriority200 = 200
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

		//dnsServerList := strings.Join(networkContainerInfo.IPConfiguration.DNSServers, ", ")
		//dnsServerList += ", " + AzureDNS
		endpoint = &hcsshim.HNSEndpoint{
			Name:           endpointName,
			IPAddress:      net.ParseIP(networkContainerInfo.IPConfiguration.IPSubnet.IPAddress),
			VirtualNetwork: networkID,
			DNSServerList:  AzureDNS, //dnsServerList,
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

func configureHostNCApipaNetwork(localIPConfiguration cns.IPConfiguration) (*hcn.HostComputeNetwork, error) {
	network := &hcn.HostComputeNetwork{
		Name: hostNCApipaNetworkName,
		Ipams: []hcn.Ipam{
			hcn.Ipam{
				Type: hcnIpamTypeStatic,
			},
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaVersionMajor,
			Minor: hcnSchemaVersionMinor,
		},
		Type:  hostNCApipaNetworkType,
		Flags: hcn.EnableNonPersistent, // Set up the network in non-persistent mode
	}

	if netAdapterNamePolicy, err := policy.GetHcnNetAdapterPolicy(hostNCLoopbackAdapterName); err == nil {
		network.Policies = append(network.Policies, netAdapterNamePolicy)
	} else {
		return nil, fmt.Errorf("Failed to serialize network adapter policy. Error: %v", err)
	}

	// Calculate subnet prefix
	// Following code calculates the subnet prefix from localIPConfiguration IP
	// e.g. IP: 169.254.128.7 Prefix length: 17 then resulting subnet prefix: 169.254.128.0/17
	// subnetPrefix: ffff8000
	// subnetPrefix.IP: 169.254.128.0
	var (
		subnetPrefix    net.IPNet
		subnetPrefixStr string
		ipAddr          net.IP
	)

	ipAddr = net.ParseIP(localIPConfiguration.IPSubnet.IPAddress)
	if ipAddr.To4() != nil {
		subnetPrefix = net.IPNet{Mask: net.CIDRMask(int(localIPConfiguration.IPSubnet.PrefixLength), 32)}
	} else if ipAddr.To16() != nil {
		subnetPrefix = net.IPNet{Mask: net.CIDRMask(int(localIPConfiguration.IPSubnet.PrefixLength), 128)}
	} else {
		return nil, fmt.Errorf("Failed get subnet prefix for localIPConfiguration: %+v", localIPConfiguration)
	}

	subnetPrefix.IP = ipAddr.Mask(subnetPrefix.Mask)
	subnetPrefixStr = subnetPrefix.IP.String() + "/" + strconv.Itoa(int(localIPConfiguration.IPSubnet.PrefixLength))

	subnet := hcn.Subnet{
		IpAddressPrefix: subnetPrefixStr,
		Routes: []hcn.Route{
			hcn.Route{
				NextHop:           localIPConfiguration.GatewayIPAddress,
				DestinationPrefix: "0.0.0.0/0",
			},
		},
	}

	network.Ipams[0].Subnets = append(network.Ipams[0].Subnets, subnet)

	log.Printf("[Azure CNS] Configured HostNCApipaNetwork: %+v", network)

	return network, nil
}

func createHostNCApipaNetwork(
	localIPConfiguration cns.IPConfiguration) (*hcn.HostComputeNetwork, error) {
	var (
		network *hcn.HostComputeNetwork
		err     error
	)

	namedLock.LockAcquire(hostNCApipaNetworkName)
	defer namedLock.LockRelease(hostNCApipaNetworkName)

	// Check if the network exists for Host NC connectivity
	if network, err = hcn.GetNetworkByName(hostNCApipaNetworkName); err != nil {
		// If error is anything other than networkNotFound, mark this as error
		if _, networkNotFound := err.(hcn.NetworkNotFoundError); !networkNotFound {
			return nil, fmt.Errorf("[Azure CNS] ERROR: createApipaNetwork failed. Error with GetNetworkByName: %v", err)
		}

		// Network doesn't exist. Create one.
		if network, err = configureHostNCApipaNetwork(localIPConfiguration); err != nil {
			return nil, fmt.Errorf("Failed to configure network. Error: %v", err)
		}

		// Create loopback adapter needed for this HNS network
		if interfaceExists, _ := networkcontainers.InterfaceExists(hostNCLoopbackAdapterName); !interfaceExists {
			ipconfig := cns.IPConfiguration{
				IPSubnet: cns.IPSubnet{
					IPAddress:    localIPConfiguration.GatewayIPAddress,
					PrefixLength: localIPConfiguration.IPSubnet.PrefixLength,
				},
				GatewayIPAddress: localIPConfiguration.GatewayIPAddress,
			}

			if err = networkcontainers.CreateLoopbackAdapter(
				hostNCLoopbackAdapterName,
				ipconfig,
				false, /* Flag to setWeakHostOnInterface */
				"" /* Empty primary Interface Identifier as setWeakHostOnInterface is not needed*/); err != nil {
				return nil, fmt.Errorf("Failed to create loopback adapter. Error: %v", err)
			}
		}

		// Create the HNS network.
		log.Printf("[Azure CNS] Creating HostNCApipaNetwork: %+v", network)

		if network, err = network.Create(); err != nil {
			return nil, err
		}

		log.Printf("[Azure CNS] Successfully created apipa network for host container connectivity: %+v", network)
	} else {
		log.Printf("[Azure CNS] Found existing HostNCApipaNetwork: %+v", network)
	}

	return network, err
}

func addAclToEndpointPolicy(
	aclPolicySetting hcn.AclPolicySetting,
	endpointPolicies *[]hcn.EndpointPolicy) error {
	var (
		rawJSON []byte
		err     error
	)

	if rawJSON, err = json.Marshal(aclPolicySetting); err != nil {
		return fmt.Errorf("Failed to marshal endpoint ACL: %+v", aclPolicySetting)
	}

	endpointPolicy := hcn.EndpointPolicy{
		Type:     hcn.ACL,
		Settings: rawJSON,
	}

	*endpointPolicies = append(*endpointPolicies, endpointPolicy)

	return nil
}

func configureAclSettingHostNCApipaEndpoint(
	protocolList []string,
	networkContainerApipaIP string,
	hostApipaIP string,
	allowNCToHostCommunication bool,
	allowHostToNCCommunication bool) ([]hcn.EndpointPolicy, error) {
	var (
		err              error
		endpointPolicies []hcn.EndpointPolicy
	)

	if allowNCToHostCommunication {
		log.Printf("[Azure CNS] Allowing NC (%s) to Host (%s) connectivity", networkContainerApipaIP, hostApipaIP)
	}

	if allowHostToNCCommunication {
		log.Printf("[Azure CNS] Allowing Host (%s) to NC (%s) connectivity", hostApipaIP, networkContainerApipaIP)
	}

	// Iterate thru the protocol list and add ACL for each
	for _, protocol := range protocolList {
		// Endpoint ACL to block all outbound traffic from the Apipa IP of the container
		outBlockAll := hcn.AclPolicySetting{
			Protocols:      protocol,
			Action:         hcn.ActionTypeBlock,
			Direction:      hcn.DirectionTypeOut,
			LocalAddresses: networkContainerApipaIP,
			RuleType:       hcn.RuleTypeSwitch,
			Priority:       aclPriority2000,
		}

		if err = addAclToEndpointPolicy(outBlockAll, &endpointPolicies); err != nil {
			return nil, err
		}

		if allowNCToHostCommunication {
			// Endpoint ACL to allow the outbound traffic from the Apipa IP of the container to
			// Apipa IP of the host only
			outAllowToHostOnly := hcn.AclPolicySetting{
				Protocols:       protocol,
				Action:          hcn.ActionTypeAllow,
				Direction:       hcn.DirectionTypeOut,
				LocalAddresses:  networkContainerApipaIP,
				RemoteAddresses: hostApipaIP,
				RuleType:        hcn.RuleTypeSwitch,
				Priority:        aclPriority200,
			}

			if err = addAclToEndpointPolicy(outAllowToHostOnly, &endpointPolicies); err != nil {
				return nil, err
			}
		}

		// Endpoint ACL to block all inbound traffic to the Apipa IP of the container
		inBlockAll := hcn.AclPolicySetting{
			Protocols:      protocol,
			Action:         hcn.ActionTypeBlock,
			Direction:      hcn.DirectionTypeIn,
			LocalAddresses: networkContainerApipaIP,
			RuleType:       hcn.RuleTypeSwitch,
			Priority:       aclPriority2000,
		}

		if err = addAclToEndpointPolicy(inBlockAll, &endpointPolicies); err != nil {
			return nil, err
		}

		if allowHostToNCCommunication {
			// Endpoint ACL to allow the inbound traffic from the apipa IP of the host to
			// the apipa IP of the container only
			inAllowFromHostOnly := hcn.AclPolicySetting{
				Protocols:       protocol,
				Action:          hcn.ActionTypeAllow,
				Direction:       hcn.DirectionTypeIn,
				LocalAddresses:  networkContainerApipaIP,
				RemoteAddresses: hostApipaIP,
				RuleType:        hcn.RuleTypeSwitch,
				Priority:        aclPriority200,
			}

			if err = addAclToEndpointPolicy(inAllowFromHostOnly, &endpointPolicies); err != nil {
				return nil, err
			}
		}
	}

	return endpointPolicies, nil
}

func configureHostNCApipaEndpoint(
	endpointName string,
	networkID string,
	localIPConfiguration cns.IPConfiguration,
	allowNCToHostCommunication bool,
	allowHostToNCCommunication bool) (*hcn.HostComputeEndpoint, error) {
	endpoint := &hcn.HostComputeEndpoint{
		Name:               endpointName,
		HostComputeNetwork: networkID,
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaVersionMajor,
			Minor: hcnSchemaVersionMinor,
		},
	}

	networkContainerApipaIP := localIPConfiguration.IPSubnet.IPAddress
	hostApipaIP := localIPConfiguration.GatewayIPAddress
	protocolList := []string{protocolICMPv4, protocolTCP, protocolUDP}

	endpointPolicies, err := configureAclSettingHostNCApipaEndpoint(
		protocolList,
		networkContainerApipaIP,
		hostApipaIP,
		allowNCToHostCommunication,
		allowHostToNCCommunication)

	if err != nil {
		log.Errorf("[Azure CNS] Failed to configure ACL for HostNCApipaEndpoint. Error: %v", err)
		return nil, err
	}

	for _, endpointPolicy := range endpointPolicies {
		endpoint.Policies = append(endpoint.Policies, endpointPolicy)
	}

	hcnRoute := hcn.Route{
		NextHop:           hostApipaIP,
		DestinationPrefix: "0.0.0.0/0",
	}

	endpoint.Routes = append(endpoint.Routes, hcnRoute)

	ipConfiguration := hcn.IpConfig{
		IpAddress:    networkContainerApipaIP,
		PrefixLength: localIPConfiguration.IPSubnet.PrefixLength,
	}

	endpoint.IpConfigurations = append(endpoint.IpConfigurations, ipConfiguration)

	log.Printf("[Azure CNS] Configured HostNCApipaEndpoint: %+v", endpoint)

	return endpoint, nil
}

// CreateHostNCApipaEndpoint creates the endpoint in the apipa network for host container connectivity
func CreateHostNCApipaEndpoint(
	networkContainerID string,
	localIPConfiguration cns.IPConfiguration,
	allowNCToHostCommunication bool,
	allowHostToNCCommunication bool) (string, error) {
	var (
		network      *hcn.HostComputeNetwork
		endpoint     *hcn.HostComputeEndpoint
		endpointName = getHostNCApipaEndpointName(networkContainerID)
		err          error
	)

	namedLock.LockAcquire(endpointName)
	defer namedLock.LockRelease(endpointName)

	// Return if the endpoint already exists
	if endpoint, err = hcn.GetEndpointByName(endpointName); err != nil {
		// If error is anything other than EndpointNotFoundError, return error.
		if _, endpointNotFound := err.(hcn.EndpointNotFoundError); !endpointNotFound {
			return "", fmt.Errorf("ERROR: Failed to query endpoint using GetEndpointByName "+
				"due to error: %v", err)
		}
	}

	if endpoint != nil {
		log.Debugf("[Azure CNS] Found existing endpoint: %+v", endpoint)
		return endpoint.Id, nil
	}

	if network, err = createHostNCApipaNetwork(localIPConfiguration); err != nil {
		log.Errorf("[Azure CNS] Failed to create HostNCApipaNetwork. Error: %v", err)
		return "", err
	}

	log.Printf("[Azure CNS] Configuring HostNCApipaEndpoint: %s, in network: %s with localIPConfig: %+v",
		endpointName, network.Id, localIPConfiguration)

	if endpoint, err = configureHostNCApipaEndpoint(
		endpointName,
		network.Id,
		localIPConfiguration,
		allowNCToHostCommunication,
		allowHostToNCCommunication); err != nil {
		log.Errorf("[Azure CNS] Failed to configure HostNCApipaEndpoint: %s. Error: %v", endpointName, err)
		return "", err
	}

	log.Printf("[Azure CNS] Creating HostNCApipaEndpoint for host container connectivity: %+v", endpoint)
	if endpoint, err = endpoint.Create(); err != nil {
		err = fmt.Errorf("Failed to create HostNCApipaEndpoint: %s. Error: %v", endpointName, err)
		log.Errorf("[Azure CNS] %s", err.Error())
		return "", err
	}

	log.Printf("[Azure CNS] Successfully created HostNCApipaEndpoint: %+v", endpoint)

	return endpoint.Id, nil
}

func getHostNCApipaEndpointName(
	networkContainerID string) string {
	return hostNCApipaEndpointNamePrefix + "-" + networkContainerID
}

func deleteNetworkByIDHnsV2(
	networkID string) error {
	var (
		network *hcn.HostComputeNetwork
		err     error
	)

	if network, err = hcn.GetNetworkByID(networkID); err != nil {
		// If error is anything other than NetworkNotFoundError, return error.
		// else log the error but don't return error because network is already deleted.
		if _, networkNotFound := err.(hcn.NetworkNotFoundError); !networkNotFound {
			return fmt.Errorf("[Azure CNS] deleteNetworkByIDHnsV2 failed due to "+
				"error with GetNetworkByID: %v", err)
		}

		log.Errorf("[Azure CNS] Delete called on the Network: %s which doesn't exist. Error: %v",
			networkID, err)

		return nil
	}

	if err = network.Delete(); err != nil {
		return fmt.Errorf("Failed to delete network: %+v. Error: %v", network, err)
	}

	log.Errorf("[Azure CNS] Successfully deleted network: %+v", network)

	return nil
}

func deleteEndpointByNameHnsV2(
	endpointName string) error {
	var (
		endpoint *hcn.HostComputeEndpoint
		err      error
	)

	// Check if the endpoint exists
	if endpoint, err = hcn.GetEndpointByName(endpointName); err != nil {
		// If error is anything other than EndpointNotFoundError, return error.
		// else log the error but don't return error because endpoint is already deleted.
		if _, endpointNotFound := err.(hcn.EndpointNotFoundError); !endpointNotFound {
			return fmt.Errorf("[Azure CNS] deleteEndpointByNameHnsV2 failed due to "+
				"error with GetEndpointByName: %v", err)
		}

		log.Errorf("[Azure CNS] Delete called on the Endpoint: %s which doesn't exist. Error: %v",
			endpointName, err)

		return nil
	}

	if err = endpoint.Delete(); err != nil {
		return fmt.Errorf("Failed to delete endpoint: %+v. Error: %v", endpoint, err)
	}

	log.Errorf("[Azure CNS] Successfully deleted endpoint: %+v", endpoint)

	return nil
}

// DeleteHostNCApipaEndpoint deletes the endpoint in the apipa network created for host container connectivity
func DeleteHostNCApipaEndpoint(
	networkContainerID string) error {
	endpointName := getHostNCApipaEndpointName(networkContainerID)

	namedLock.LockAcquire(endpointName)
	defer namedLock.LockRelease(endpointName)

	log.Debugf("[Azure CNS] Deleting HostNCApipaEndpoint: %s", endpointName)

	if err := deleteEndpointByNameHnsV2(endpointName); err != nil {
		log.Errorf("[Azure CNS] Failed to delete HostNCApipaEndpoint: %s. Error: %v", endpointName, err)
		return err
	}

	log.Debugf("[Azure CNS] Successfully deleted HostNCApipaEndpoint: %s", endpointName)

	namedLock.LockAcquire(hostNCApipaNetworkName)
	defer namedLock.LockRelease(hostNCApipaNetworkName)

	// Check if hostNCApipaNetworkName has any endpoints left
	if network, err := hcn.GetNetworkByName(hostNCApipaNetworkName); err == nil {
		var endpoints []hcn.HostComputeEndpoint
		if endpoints, err = hcn.ListEndpointsOfNetwork(network.Id); err != nil {
			log.Errorf("[Azure CNS] Failed to list endpoints in the network: %s. Error: %v",
				hostNCApipaNetworkName, err)
			return nil
		}

		// Delete network if it doesn't have any endpoints
		if len(endpoints) == 0 {
			log.Debugf("[Azure CNS] Deleting network with ID: %s", network.Id)
			if err = deleteNetworkByIDHnsV2(network.Id); err == nil {
				// Delete the loopback adapter created for this network
				networkcontainers.DeleteLoopbackAdapter(hostNCLoopbackAdapterName)
			}
		}
	}

	return nil
}

// SetupNetworkAndEndpoints sets up network and endpoint for the specified network
// container and windows network compartment ID
func SetupNetworkAndEndpoints2(
	networkContainerInfo *cns.GetNetworkContainerResponse, ncID string) (int, error) {
	log.Printf("[Azure CNS] SetupNetworkAndEndpoints2")
	var (
		err              error
		network          *hcn.HostComputeNetwork
		endpoint         *hcn.HostComputeEndpoint
		networkNamespace *hcn.HostComputeNamespace
		endpointName     = ncID
	)

	//////////////////////////////////////////////////
	networkNamespaceObj := hcn.NewNamespace(hcn.NamespaceTypeHost)
	if networkNamespace, err = networkNamespaceObj.Create(); err != nil {
		log.Errorf("[Azure CNS] Failed to create networkNamespace. Error: %v", err)
		return 0, err
	}

	log.Printf("Successfully created network compartment %+v", networkNamespace)

	// Create namespace and attach dummy container to it.
	mapC := map[string]string{"ContainerId": "700"}
	settingsJSON, errJSON := json.Marshal(mapC)
	if errJSON != nil {
		log.Printf("ashvind: failed to marshal the containerId map for settingsJson due to error %v", errJSON)
		return 0, nil
	}
	requestMessage := &hcn.ModifyNamespaceSettingRequest{
		ResourceType: hcn.NamespaceResourceTypeContainer,
		RequestType:  hcn.RequestTypeAdd,
		Settings:     settingsJSON}

	if errMod := hcn.ModifyNamespaceSettings(networkNamespace.Id, requestMessage); errMod != nil {
		log.Printf("ashvind: ModifyNamespaceSettings failed with error: %v", errMod)
	} else {
		log.Printf("ashvind: ModifyNamespaceSettings SUCCESS")
		networkNamespace, err = hcn.GetNamespaceByID(networkNamespace.Id)
		if err == nil {
			log.Printf("ashvind retrieved compartmentId: %d", networkNamespace.NamespaceId)
			if containers, err := hcn.GetNamespaceContainerIds(networkNamespace.Id); err == nil {
				if len(containers) > 0 {
					for index, elem := range containers {
						log.Printf("ashvind: containers: [%d] -> [%v]", index, elem)
					}
				}
			}
		}
	}

	/////////////////////////////////////////////////

	if network, err = createNetworkWithNC2(networkContainerInfo); err != nil {
		return 0, err
	}

	namedLock.LockAcquire(endpointName)
	defer namedLock.LockRelease(endpointName)

	if endpoint, err = createEndpointWithNC2(networkContainerInfo, ncID, network.Id); err != nil {
		return 0, err
	}

	///////////////////////////////
	// Attach endpoint to compartment

	if err = hcn.AddNamespaceEndpoint(networkNamespace.Id, endpoint.Id); err != nil {
		return 0, fmt.Errorf("[Azure CNS] Failed to add endpoint: %s to namespace: %s due to error: %v",
			endpoint.Id, networkNamespace.Id, err)
	}

	// Get the compartmentId from the createdNamespace
	var compartmentID uint32
	if networkNamespace, err = hcn.GetNamespaceByID(networkNamespace.Id); err == nil { // ashvind - is this needed?
		compartmentID = networkNamespace.NamespaceId
		log.Printf("ashvind retrieved compartmentId: %d", compartmentID)
	} else {
		log.Printf("ashvind ERROR cannot retrieve compartmentId")
	}

	log.Printf("[Azure CNS] Successfully attached endpoint %s to compartment %s with id %d",
		endpointName, networkNamespace.Id, networkNamespace.NamespaceId)

	//////////////////////////////

	return (int)(compartmentID), nil
}

// Create network to hold the endpoint for the specified NC
func createNetworkWithNC2(
	networkContainerInfo *cns.GetNetworkContainerResponse) (*hcn.HostComputeNetwork, error) {
	var (
		err                error
		networkName        string
		networkAdapterName string
		network            *hcn.HostComputeNetwork
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
	subnetPrefixStr := subnetPrefix.IP.String() + "/" + strconv.Itoa(int(networkContainerInfo.IPConfiguration.IPSubnet.PrefixLength))

	if networkName, err = GetNetworkNameForNC(networkContainerInfo); err != nil {
		return nil, fmt.Errorf("[Azure CNS] ERROR: Failed to get network name due to error: %v", err)
	}

	namedLock.LockAcquire(networkName)
	defer namedLock.LockRelease(networkName)

	// Check if the network already exists
	if network, err = hcn.GetNetworkByName(networkName); err != nil {
		// If error is anything other than networkNotFound return error
		if _, networkNotFound := err.(hcn.NetworkNotFoundError); !networkNotFound {
			return nil, fmt.Errorf("[Azure CNS] ERROR: Failed GetHNSNetworkByName due to error: %v", err)
		}

		// Get network adapter name
		if networkAdapterName, err = GetNetworkAdapterNameForNC(networkContainerInfo); err != nil {
			log.Errorf("[Azure CNS] Failed to get network adapter name due to error: %v", err)
			return nil, fmt.Errorf("Failed to get network adapter name due to error: %v", err)
		}

		// Create the network.
		log.Printf("[Azure CNS] Creating network %s", networkName)
		//dnsServerList := strings.Join(networkContainerInfo.IPConfiguration.DNSServers, ", ")
		//dnsServerList += ", " + AzureDNS

		network, err = configureNetworkHnsV2(
			networkName,
			networkAdapterName,
			networkContainerInfo.MultiTenancyInfo.ID,
			subnetPrefixStr,
			networkContainerInfo.IPConfiguration.GatewayIPAddress)
		if err != nil {
			log.Printf("[Azure CNS] Failed to configure network %+v", network)
			return nil, err
		}

		// Create HNS network.
		if network, err = network.Create(); err != nil {
			return nil, err
		}

		log.Printf("[Azure CNS] Successfully created network: %+v", network)
	} else {
		log.Printf("[Azure CNS] Network is already present. Network: %+v", network)
	}

	return network, nil
}

// Create endpoint for the specified NC
func createEndpointWithNC2(
	networkContainerInfo *cns.GetNetworkContainerResponse,
	ncID string,
	networkID string) (*hcn.HostComputeEndpoint, error) {
	var (
		err          error
		hcnEndpoint  *hcn.HostComputeEndpoint
		endpointName = ncID
	)

	// Check if the endpoint already exists
	if hcnEndpoint, err = hcn.GetEndpointByName(endpointName); err != nil {
		// If error is anything other than endpointNotFound return error
		if _, endpointNotFound := err.(hcn.EndpointNotFoundError); !endpointNotFound {
			return nil, fmt.Errorf("[Azure CNS] ERROR: Failed GetHNSEndpointByName due to error: %v", err)
		}

		hcnEndpoint = &hcn.HostComputeEndpoint{
			Name:               endpointName,
			HostComputeNetwork: networkID,
			Dns: hcn.Dns{
				//Search:     strings.Split(epInfo.DNS.Suffix, ","),
				//ServerList: epInfo.DNS.Servers,
				ServerList: strings.Split(AzureDNS, ","),
				//Options:    epInfo.DNS.Options,
			},
			SchemaVersion: hcn.SchemaVersion{
				Major: hcnSchemaVersionMajor,
				Minor: hcnSchemaVersionMinor,
			},
			//MacAddress: epInfo.MacAddress.String(),
		}

		////////////////////////////////////////

		outBoundNATPolicy := hcn.EndpointPolicy{
			Type: hcn.OutBoundNAT,
		}

		outBoundNATPolicySetting := hcn.OutboundNatPolicySetting{}

		for _, ipAddress := range networkContainerInfo.CnetAddressSpace {
			outBoundNATPolicySetting.Exceptions = append(outBoundNATPolicySetting.Exceptions,
				ipAddress.IPAddress+"/"+strconv.Itoa(int(ipAddress.PrefixLength)))
		}

		if outBoundNATPolicySetting.Exceptions != nil {
			outBoundNATPolicySettingBytes, err := json.Marshal(outBoundNATPolicySetting)
			if err != nil {
				log.Errorf("[Azure CNS] Failed to marshal outboundNAT policy. Error: %v", err)
				return nil, err
			}

			outBoundNATPolicy.Settings = outBoundNATPolicySettingBytes

			hcnEndpoint.Policies = append(hcnEndpoint.Policies, outBoundNATPolicy)
		}

		//return outBoundNATPolicy, fmt.Errorf("OutBoundNAT policy not set")
		/*
			if endpointPolicies, err := policy.GetHcnEndpointPolicies(policy.EndpointPolicy, epInfo.Policies, epInfo.Data); err == nil {
				for _, epPolicy := range endpointPolicies {
					hcnEndpoint.Policies = append(hcnEndpoint.Policies, epPolicy)
				}
			} else {
				log.Printf("[net] Failed to get endpoint policies due to error: %v", err)
				return nil, err
			}
		*/

		// TODO: Check if the route is populated - I dont think so.
		/*
			for _, route := range epInfo.Routes {
				hcnRoute := hcn.Route{
					NextHop:           route.Gw.String(),
					DestinationPrefix: route.Dst.String(),
				}

				hcnEndpoint.Routes = append(hcnEndpoint.Routes, hcnRoute)
			}
		*/

		ipConfiguration := hcn.IpConfig{
			IpAddress:    networkContainerInfo.IPConfiguration.IPSubnet.IPAddress,
			PrefixLength: uint8(networkContainerInfo.IPConfiguration.IPSubnet.PrefixLength),
		}

		hcnEndpoint.IpConfigurations = append(hcnEndpoint.IpConfigurations, ipConfiguration)

		log.Printf("[Azure CNS] Creating Endpoint: %+v", hcnEndpoint)
		if hcnEndpoint, err = hcnEndpoint.Create(); err != nil {
			err = fmt.Errorf("Failed to create Endpoint: %s. Error: %v", endpointName, err)
			log.Errorf("[Azure CNS] %s", err.Error())
			return nil, err
		}

		/////////////////////////////////////////

		log.Printf("[Azure CNS] Successfully created endpoint: %+v", hcnEndpoint)
	} else {
		log.Printf("[Azure CNS] ERROR: Endpoint is already present. Endpoint: %+v", hcnEndpoint)
		return nil, fmt.Errorf("[Azure CNS] ERROR: Endpoint: %s already present.", endpointName)
	}

	return hcnEndpoint, nil
}

func configureNetworkHnsV2(
	networkName string,
	networkAdapterName string,
	vlanID int,
	subnetPrefixStr string,
	gateway string) (*hcn.HostComputeNetwork, error) {
	var err error
	network := &hcn.HostComputeNetwork{
		Name: networkName,
		Dns: hcn.Dns{
			ServerList: strings.Split(AzureDNS, ","),
		},
		Ipams: []hcn.Ipam{
			hcn.Ipam{
				Type: hcnIpamTypeStatic,
			},
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaVersionMajor,
			Minor: hcnSchemaVersionMinor,
		},
		Type:  hostNCApipaNetworkType,
		Flags: hcn.EnableNonPersistent, // Set up the network in non-persistent mode
	}

	if netAdapterNamePolicy, err := policy.GetHcnNetAdapterPolicy(networkAdapterName); err == nil {
		network.Policies = append(network.Policies, netAdapterNamePolicy)
	} else {
		return nil, fmt.Errorf("Failed to serialize network adapter policy. Error: %v", err)
	}

	var subnetPolicy []byte

	subnetPolicy, err = policy.SerializeHcnSubnetVlanPolicy((uint32)(vlanID))
	if err != nil {
		log.Printf("[net] Failed to serialize subnet vlan policy due to error: %v", err)
		return nil, err
	}

	subnet := hcn.Subnet{
		IpAddressPrefix: subnetPrefixStr,
		Routes: []hcn.Route{
			hcn.Route{
				NextHop:           gateway,
				DestinationPrefix: "0.0.0.0/0",
			},
		},
	}

	subnet.Policies = append(subnet.Policies, subnetPolicy)

	network.Ipams[0].Subnets = append(network.Ipams[0].Subnets, subnet)

	log.Printf("[Azure CNS] Configured HostNCApipaNetwork: %+v", network)

	return network, nil
}
