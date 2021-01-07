package dncclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"testing"

	"context"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/configuration"
	"github.com/Azure/azure-container-networking/cns/logger"
	acncommon "github.com/Azure/azure-container-networking/common"
)

const (
	dncEndpoint = "localhost:9000"
)

type fakeTokenFetcher struct{}

func (f *fakeTokenFetcher) GetOAuthToken(ctx context.Context, resource string) (string, error) {
	return "dummyToken", nil
}

func dncRequestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(acncommon.ContentType, acncommon.JsonContent)

	info := &cns.SetOrchestratorTypeRequest{
		OrchestratorType: "Kubernetes",
		DncPartitionKey:  "testPKey",
		NodeID:           "testNodeID",
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(info)
	/*
		if strings.Contains(r.RequestURI, "networkcontainers") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"httpStatusCode":"200","networkContainerId":"nc-nma-success","version":"0"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"httpStatusCode":"200","networkContainerId":"nc-nma-fail-version-mismatch","version":"0"}`))
	*/
}

func createDNCClient() *DNCClient {
	var fakeTokenFetcher fakeTokenFetcher
	testCNSConfig := configuration.CNSConfig{
		ManagedSettings: configuration.ManagedSettings{
			DncEndpointDns:            "tcp://localhost:9000",
			InfrastructureNetworkID:   "mockVnetID",
			NodeID:                    "mockNodeID",
			NodeManagedIdentity:       "mockManagedIdentity",
			NodeSyncIntervalInSeconds: 30,
		},
		HttpClientSettings: configuration.HttpClientSettings{
			ConnectionTimeout:     5,
			ResponseHeaderTimeout: 5,
		},
	}

	return NewDNCClient(&fakeTokenFetcher, &testCNSConfig)
}

func TestMain(m *testing.M) {
	logger.InitLogger("testlogs", 0, 0, "./")

	// Setup mock DNC server
	dncServer, err := setupMockDNCServer()
	if err != nil {
		return
	}

	// Run tests.
	exitCode := m.Run()

	// Cleanup.
	dncServer.Stop()
	os.Exit(exitCode)
}

func setupMockDNCServer() (*acncommon.Listener, error) {
	u, err := url.Parse("tcp://" + dncEndpoint)
	if err != nil {
		fmt.Println(err.Error())
	}

	dncServer, err := acncommon.NewListener(u)
	if err != nil {
		fmt.Println(err.Error())
	}

	dncServer.AddHandler("/", dncRequestHandler)
	err = dncServer.Start(make(chan error, 1))
	if err != nil {
		fmt.Printf("Failed to start Mock DNC Server, err:%v", err)
		return nil, err
	}

	return dncServer, nil
}

// TestSyncNodeNcStatusFailCase tests the case when SyncNodeNcStatus is called
// without registering the node. This is expected to fail.

/*func TestSyncNodeNcStatusFailCase(t *testing.T) {
	dncClient := createDNCClient()
	nodeInfo, err := dncClient.SyncNodeNcStatus()
	// check if the error returned matches the one that DNC sent.
}
*/

func TestRegisterNode(t *testing.T) {
	dncClient := createDNCClient()
	// todo: check if the bearer token is sent to the dnc server.
	orchestratorDetails := dncClient.RegisterNode()
	expectedOrchestratorDetails := cns.SetOrchestratorTypeRequest{
		OrchestratorType: "Kubernetes",
		DncPartitionKey:  "testPKey",
		NodeID:           "testNodeID",
	}

	if !reflect.DeepEqual(orchestratorDetails, expectedOrchestratorDetails) {
		t.Fatalf("RegisterNode failed. \n\nExpected OrchestratorContext: %+v\n\nReceived OrchestratorContext: %+v",
			expectedOrchestratorDetails, orchestratorDetails)
	}

	//todo: add test cases for failure case of register node.
}
