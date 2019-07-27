package hnsclient

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/log"
	//"github.com/Azure/azure-container-networking/cns"
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
	acnBinaryName = "acn.exe"
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

	return createHnsNetwork(hnsNetwork)
}

// DeleteHnsNetwork deletes the HNS network with the provided name
func DeleteHnsNetwork(networkName string) error {
	log.Printf("[Azure CNS] DeleteHnsNetwork")

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

	// Create the HNS network.
	log.Printf("[Azure CNS] HNSNetworkRequest POST request:%+v", hnsRequest)
	hnsResponse, err := hcsshim.HNSNetworkRequest("POST", "", hnsRequest)
	log.Printf("[Azure CNS] HNSNetworkRequest POST response:%+v err:%v.", hnsResponse, err)

	return err
}

// deleteHnsNetwork calls HNS to delete the network with the provided name
func deleteHnsNetwork(networkName string) error {
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err == nil {
		// Delete the HNS network.
		var hnsResponse *hcsshim.HNSNetwork
		log.Printf("[Azure CNS] HNSNetworkRequest DELETE id:%v", hnsNetwork.Id)
		hnsResponse, err = hcsshim.HNSNetworkRequest("DELETE", hnsNetwork.Id, "")
		log.Printf("[Azure CNS] HNSNetworkRequest DELETE response:%+v err:%v.", hnsResponse, err)
	}

	return err
}

// CreateCompartment creates windows network compartment
func CreateCompartment() (int, error) {
	log.Printf("[Azure CNS] CreateCompartment")

	var (
		err           error
		compartmentID int
		bytes         []byte
	)

	if _, err = os.Stat(acnBinaryName); err != nil {
		log.Printf("[Azure CNS] ERROR: Unable to find %s needed for compartment creation", acnBinaryName)
		return compartmentID, fmt.Errorf("ERROR: Unable to create the compartment")
	}

	//TODO: Is parsing the output the best way to get this
	args := []string{"/C", acnBinaryName, "/operation", "create"}
	log.Printf("[Azure CNS] Calling acn with args: %v", args)
	c := exec.Command("cmd", args...)
	if bytes, err = c.Output(); err != nil {
		return compartmentID, fmt.Errorf("ERROR: Failed to create compartment due to error: %s", bytes)
	}

	if compartmentID, err = strconv.Atoi(strings.TrimSpace(string(bytes))); err != nil {
		log.Printf("[Azure CNS] Unable to parse output from acn.exe")
		return compartmentID, fmt.Errorf("ERROR: Failed to create compartment due to error: %v", err)
	}

	return compartmentID, nil
}

// DeleteCompartment deletes windows network compartment
func DeleteCompartment(compartmentID int) error {
	log.Printf("[Azure CNS] DeleteCompartment")

	var (
		err   error
		bytes []byte
	)

	if _, err = os.Stat(acnBinaryName); err != nil {
		log.Printf("[Azure CNS] ERROR: Unable to find %s needed for compartment deletion", acnBinaryName)
		return fmt.Errorf("ERROR: Unable to delete the compartment")
	}

	args := []string{"/C", acnBinaryName, "/operation", "delete", strconv.Itoa(compartmentID)}
	log.Printf("[Azure CNS] Calling acn with args: %v", args)
	c := exec.Command("cmd", args...)
	if bytes, err = c.Output(); err != nil {
		return fmt.Errorf("ERROR: Failed to create compartment due to error: %s", bytes)
	}

	log.Printf("[Azure CNS] Successfully deleted network compartment with ID: %d", compartmentID)

	return nil
}

// CleanupEndpoint detaches endpoint from the host and deletes it
func CleanupEndpoint(endpointName string) error {
	log.Printf("[Azure CNS] CleanupEndpoint")
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
	log.Printf("[Azure CNS] Deleting HNS endpoint: %+v", endpoint)
	if _, err = hcsshim.HNSEndpointRequest("DELETE", endpoint.Id, ""); err != nil {
		return fmt.Errorf("ERROR: Failed to delete endpoint: %v due to error: %v", endpoint, err)
	}

	log.Printf("[Azure CNS] Successfully deleted endpoint: %s", endpointName)

	return nil
}
