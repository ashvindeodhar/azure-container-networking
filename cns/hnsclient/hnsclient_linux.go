package hnsclient

import (
	"fmt"

	"github.com/Azure/azure-container-networking/cns"
)

const (
	// Default network compartment ID
	DefaultNetworkCompartmentID = 1

	// Maximum number of Network containers allowed in the network compartment
	MaxNCsPerCompartment = 0
)

// CreateDefaultExtNetwork creates the default ext network (if it doesn't exist already)
// to create external switch on windows platform.
// This is windows platform specific.
func CreateDefaultExtNetwork(networkType string) error {
	return fmt.Errorf("[Azure CNS] CreateDefaultExtNetwork shouldn't be called for linux platform")
}

// DeleteDefaultExtNetwork deletes the default HNS network.
// This is windows platform specific.
func DeleteDefaultExtNetwork() error {
	return fmt.Errorf("[Azure CNS] DeleteDefaultExtNetwork shouldn't be called for linux platform")
}

// CreateHnsNetwork creates the HNS network with the provided configuration
// This is windows platform specific.
func CreateHnsNetwork(nwConfig cns.CreateHnsNetworkRequest) error {
	return fmt.Errorf("[Azure CNS] CreateHnsNetwork shouldn't be called for linux platform")
}

// DeleteHnsNetwork deletes the HNS network with the provided name.
// This is windows platform specific.
func DeleteHnsNetwork(networkName string) error {
	return fmt.Errorf("[Azure CNS] DeleteHnsNetwork shouldn't be called for linux platform")
}

// CreateCompartment creates windows network compartment
// This is windows platform specific.
func CreateCompartment() (int, error) {
	return 0, fmt.Errorf("[Azure CNS] CreateCompartment shouldn't be called for linux platform")
}

// DeleteCompartment deletes windows network compartment
// This is windows platform specific.
func DeleteCompartment(compartmentID int) error {
	return fmt.Errorf("[Azure CNS] DeleteCompartment shouldn't be called for linux platform")
}

// CleanupEndpoint detaches endpoint from the host and deletes it
// This is windows platform specific.
func CleanupEndpoint(endpointName string) error {
	return fmt.Errorf("[Azure CNS] CleanupEndpoint shouldn't be called for linux platform")
}

// SetupNetworkAndEndpoints sets up network and endpoint for the specified network
// container and windows network compartment ID
// This is windows platform specific.
func SetupNetworkAndEndpoints(
	networkContainerInfo *cns.GetNetworkContainerResponse, ncID string, compartmentID int) error {
	return fmt.Errorf("[Azure CNS] SetupNetworkAndEndpoints shouldn't be called for linux platform")
}

// GetNetworkNameForNC gets the name of the network for the given NC
// This is windows platform specific.
func GetNetworkNameForNC(networkContainerInfo *cns.GetNetworkContainerResponse) (string, error) {
	return "", fmt.Errorf("[Azure CNS] GetNetworkNameForNC shouldn't be called for linux platform")
}

// IsCompartmentManagementSupported validates if the compartment management feature can be supported
// This is windows platform specific.
func IsCompartmentManagementSupported() error {
	return fmt.Errorf("[Azure CNS] IsCompartmentManagementSupported shouldn't be called for linux platform")
}
