// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package restserver

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/common"
	acncommon "github.com/Azure/azure-container-networking/common"
	"github.com/Azure/azure-container-networking/platform"
	"github.com/Azure/azure-container-networking/store"
)

type IPAddress struct {
	XMLName   xml.Name `xml:"IPAddress"`
	Address   string   `xml:"Address,attr"`
	IsPrimary bool     `xml:"IsPrimary,attr"`
}
type IPSubnet struct {
	XMLName   xml.Name `xml:"IPSubnet"`
	Prefix    string   `xml:"Prefix,attr"`
	IPAddress []IPAddress
}

type Interface struct {
	XMLName    xml.Name `xml:"Interface"`
	MacAddress string   `xml:"MacAddress,attr"`
	IsPrimary  bool     `xml:"IsPrimary,attr"`
	IPSubnet   []IPSubnet
}

type xmlDocument struct {
	XMLName   xml.Name `xml:"Interfaces"`
	Interface []Interface
}

var (
	service                               HTTPService
	mux                                   *http.ServeMux
	hostQueryForProgrammedVersionResponse = `{"httpStatusCode":"200","networkContainerId":"eab2470f-test-test-test-b3cd316979d5","version":"1"}`
	hostQueryResponse                     = xmlDocument{
		XMLName: xml.Name{Local: "Interfaces"},
		Interface: []Interface{Interface{
			XMLName:    xml.Name{Local: "Interface"},
			MacAddress: "*",
			IsPrimary:  true,
			IPSubnet: []IPSubnet{
				IPSubnet{XMLName: xml.Name{Local: "IPSubnet"},
					Prefix: "10.0.0.0/16",
					IPAddress: []IPAddress{
						IPAddress{
							XMLName:   xml.Name{Local: "IPAddress"},
							Address:   "10.0.0.4",
							IsPrimary: true},
					}},
			},
		}},
	}
)

func getInterfaceInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	output, _ := xml.Marshal(hostQueryResponse)
	w.Write(output)
}

func getContainerInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(hostQueryForProgrammedVersionResponse))
}

// Wraps the test run with service setup and teardown.
func TestMain(m *testing.M) {
	var config common.ServiceConfig
	var err error

	err = acncommon.CreateDirectory(platform.CNMRuntimePath)
	if err != nil {
		fmt.Printf("Failed to create File Store directory Error:%v", err.Error())
		os.Exit(1)
	}

	// Create the key value store.
	config.Store, err = store.NewJsonFileStore("azure-cns.json")
	if err != nil {
		fmt.Printf("Failed to create store: %v\n", err)
		os.Exit(1)
	}

	// Create the service.
	service, err = NewHTTPRestService(&config)
	if err != nil {
		fmt.Printf("Failed to create CNS object %v\n", err)
		os.Exit(1)
	}

	// Configure test mode.
	service.(*HTTPRestService).Name = "cns-test-server"
	//service.(*HTTPRestService).imdsClient.HostQueryURL = imdsclient.HostQueryURL
	//service.(*HTTPRestService).imdsClient.HostQueryURLForProgrammedVersion = imdsclient.HostQueryURLForProgrammedVersion
	// Following HostQueryURL and HostQueryURLForProgrammedVersion are only for mock environment.
	//service.(*httpRestService).imdsClient.HostQueryURL = "http://localhost:9000/getInterface"
	//service.(*httpRestService).imdsClient.HostQueryURLForProgrammedVersion = "http://localhost:9000/machine/plugins/?comp=nmagent&type=NetworkManagement/interfaces/%s/networkContainers/%s/authenticationToken/%s/api-version/%s"

	// Start the service.
	err = service.Start(&config)
	if err != nil {
		fmt.Printf("Failed to start CNS %v\n", err)
		os.Exit(2)
	}

	// Get the internal http mux as test hook.
	mux = service.(*HTTPRestService).Listener.GetMux()

	// Setup mock nmagent server
	u, err := url.Parse("tcp://localhost:9000")
	if err != nil {
		fmt.Println(err.Error())
	}

	nmAgentServer, err := acncommon.NewListener(u)
	if err != nil {
		fmt.Println(err.Error())
	}

	nmAgentServer.AddHandler("/getInterface", getInterfaceInfo)
	nmAgentServer.AddHandler("machine/plugins/?comp=nmagent&type=NetworkManagement/interfaces/{interface}/networkContainers/{networkContainer}/authenticationToken/{authToken}/api-version/{version}", getContainerInfo)

	err = nmAgentServer.Start(make(chan error, 1))
	if err != nil {
		fmt.Printf("Failed to start agent, err:%v.\n", err)
		return
	}

	// Run tests.
	exitCode := m.Run()

	// Cleanup.
	service.Stop()

	os.Exit(exitCode)
}

// Decodes service's responses to test requests.
func decodeResponse(w *httptest.ResponseRecorder, response interface{}) error {
	if w.Code != http.StatusOK {
		return fmt.Errorf("Request failed with HTTP error %d", w.Code)
	}

	if w.Result().Body == nil {
		return fmt.Errorf("Response body is empty")
	}

	return json.NewDecoder(w.Body).Decode(&response)
}

func setEnv(t *testing.T) *httptest.ResponseRecorder {
	envRequest := cns.SetEnvironmentRequest{Location: "Azure", NetworkType: "Underlay"}
	envRequestJSON := new(bytes.Buffer)
	json.NewEncoder(envRequestJSON).Encode(envRequest)

	req, err := http.NewRequest(http.MethodPost, cns.V2Prefix+cns.SetEnvironmentPath, envRequestJSON)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestSetEnvironment(t *testing.T) {
	fmt.Println("Test: SetEnvironment")

	var resp cns.Response
	w := setEnv(t)

	err := decodeResponse(w, &resp)
	if err != nil || resp.ReturnCode != 0 {
		t.Errorf("SetEnvironment failed with response %+v", resp)
	} else {
		fmt.Printf("SetEnvironment Responded with %+v\n", resp)
	}
}

// Tests CreateNetwork functionality.
func TestCreateNetwork(t *testing.T) {
	fmt.Println("Test: CreateNetwork")

	var body bytes.Buffer
	setEnv(t)
	info := &cns.CreateNetworkRequest{
		NetworkName: "azurenet",
	}

	json.NewEncoder(&body).Encode(info)

	req, err := http.NewRequest(http.MethodPost, cns.CreateNetworkPath, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var resp cns.Response

	err = decodeResponse(w, &resp)
	if err != nil || resp.ReturnCode != 0 {
		t.Errorf("CreateNetwork failed with response %+v", resp)
	} else {
		fmt.Printf("CreateNetwork Responded with %+v\n", resp)
	}
}

// Tests DeleteNetwork functionality.
func TestDeleteNetwork(t *testing.T) {
	fmt.Println("Test: DeleteNetwork")

	var body bytes.Buffer
	setEnv(t)
	info := &cns.DeleteNetworkRequest{
		NetworkName: "azurenet",
	}

	json.NewEncoder(&body).Encode(info)

	req, err := http.NewRequest(http.MethodPost, cns.DeleteNetworkPath, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var resp cns.Response

	err = decodeResponse(w, &resp)
	if err != nil || resp.ReturnCode != 0 {
		t.Errorf("DeleteNetwork failed with response %+v", resp)
	} else {
		fmt.Printf("DeleteNetwork Responded with %+v\n", resp)
	}
}

func TestReserveIPAddress(t *testing.T) {
	fmt.Println("Test: ReserveIPAddress")

	reserveIPRequest := cns.ReserveIPAddressRequest{ReservationID: "ip01"}
	reserveIPRequestJSON := new(bytes.Buffer)
	json.NewEncoder(reserveIPRequestJSON).Encode(reserveIPRequest)
	envRequest := cns.SetEnvironmentRequest{Location: "Azure", NetworkType: "Underlay"}
	envRequestJSON := new(bytes.Buffer)
	json.NewEncoder(envRequestJSON).Encode(envRequest)

	req, err := http.NewRequest(http.MethodPost, cns.ReserveIPAddressPath, envRequestJSON)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var reserveIPAddressResponse cns.ReserveIPAddressResponse

	err = decodeResponse(w, &reserveIPAddressResponse)
	if err != nil || reserveIPAddressResponse.Response.ReturnCode != 0 {
		t.Errorf("SetEnvironment failed with response %+v", reserveIPAddressResponse)
	} else {
		fmt.Printf("SetEnvironment Responded with %+v\n", reserveIPAddressResponse)
	}
}

func TestReleaseIPAddress(t *testing.T) {
	fmt.Println("Test: ReleaseIPAddress")

	releaseIPRequest := cns.ReleaseIPAddressRequest{ReservationID: "ip01"}
	releaseIPAddressRequestJSON := new(bytes.Buffer)
	json.NewEncoder(releaseIPAddressRequestJSON).Encode(releaseIPRequest)

	req, err := http.NewRequest(http.MethodPost, cns.ReleaseIPAddressPath, releaseIPAddressRequestJSON)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var releaseIPAddressResponse cns.Response

	err = decodeResponse(w, &releaseIPAddressResponse)
	if err != nil || releaseIPAddressResponse.ReturnCode != 0 {
		t.Errorf("SetEnvironment failed with response %+v", releaseIPAddressResponse)
	} else {
		fmt.Printf("SetEnvironment Responded with %+v\n", releaseIPAddressResponse)
	}
}

func TestGetIPAddressUtilization(t *testing.T) {
	fmt.Println("Test: GetIPAddressUtilization")

	req, err := http.NewRequest(http.MethodGet, cns.GetIPAddressUtilizationPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var iPAddressesUtilizationResponse cns.IPAddressesUtilizationResponse

	err = decodeResponse(w, &iPAddressesUtilizationResponse)
	if err != nil || iPAddressesUtilizationResponse.Response.ReturnCode != 0 {
		t.Errorf("GetIPAddressUtilization failed with response %+v\n", iPAddressesUtilizationResponse)
	} else {
		fmt.Printf("GetIPAddressUtilization Responded with %+v\n", iPAddressesUtilizationResponse)
	}
}

func TestGetHostLocalIP(t *testing.T) {
	fmt.Println("Test: GetHostLocalIP")

	setEnv(t)

	req, err := http.NewRequest(http.MethodGet, cns.GetHostLocalIPPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var hostLocalIPAddressResponse cns.HostLocalIPAddressResponse

	err = decodeResponse(w, &hostLocalIPAddressResponse)
	if err != nil || hostLocalIPAddressResponse.Response.ReturnCode != 0 {
		t.Errorf("GetHostLocalIP failed with response %+v", hostLocalIPAddressResponse)
	} else {
		fmt.Printf("GetHostLocalIP Responded with %+v\n", hostLocalIPAddressResponse)
	}
}

func TestGetUnhealthyIPAddresses(t *testing.T) {
	fmt.Println("Test: GetGhostIPAddresses")

	req, err := http.NewRequest(http.MethodGet, cns.GetUnhealthyIPAddressesPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var getIPAddressesResponse cns.GetIPAddressesResponse

	err = decodeResponse(w, &getIPAddressesResponse)
	if err != nil || getIPAddressesResponse.Response.ReturnCode != 0 {
		t.Errorf("GetUnhealthyIPAddresses failed with response %+v", getIPAddressesResponse)
	} else {
		fmt.Printf("GetUnhealthyIPAddresses Responded with %+v\n", getIPAddressesResponse)
	}
}

func setOrchestratorType(t *testing.T, orchestratorType string) error {
	var body bytes.Buffer

	info := &cns.SetOrchestratorTypeRequest{OrchestratorType: orchestratorType}

	json.NewEncoder(&body).Encode(info)

	req, err := http.NewRequest(http.MethodPost, cns.SetOrchestratorType, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp cns.Response
	err = decodeResponse(w, &resp)
	fmt.Printf("Raw response: %+v", w.Body)
	if err != nil || resp.ReturnCode != 0 {
		t.Errorf("setOrchestratorType failed with response %+v Err:%+v", resp, err)
		t.Fatal(err)
	} else {
		fmt.Printf("setOrchestratorType passed with response %+v Err:%+v", resp, err)
	}

	fmt.Printf("setOrchestratorType succeeded with response %+v\n", resp)
	return nil
}

func creatOrUpdateNetworkContainerWithName(
	t *testing.T, createNetworkContainerRequest *cns.CreateNetworkContainerRequest) error {
	var body bytes.Buffer
	json.NewEncoder(&body).Encode(createNetworkContainerRequest)

	req, err := http.NewRequest(http.MethodPost, cns.CreateOrUpdateNetworkContainer, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var resp cns.CreateNetworkContainerResponse
	err = decodeResponse(w, &resp)

	if err != nil || resp.Response.ReturnCode != 0 {
		t.Errorf("CreateNetworkContainerRequest failed with response %+v Err:%+v", resp, err)
		t.Fatal(err)
	} else {
		fmt.Printf("CreateNetworkContainerRequest passed with response %+v Err:%+v", resp, err)
	}

	fmt.Printf("CreateNetworkContainerRequest succeeded with response %+v\n", resp)
	return nil
}

func deleteNetworkAdapterWithName(t *testing.T, name string) error {
	var body bytes.Buffer
	var resp cns.DeleteNetworkContainerResponse

	deleteInfo := &cns.DeleteNetworkContainerRequest{
		NetworkContainerid: name,
	}

	json.NewEncoder(&body).Encode(deleteInfo)
	req, err := http.NewRequest(http.MethodPost, cns.DeleteNetworkContainer, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	err = decodeResponse(w, &resp)
	if err != nil || resp.Response.ReturnCode != 0 {
		t.Errorf("DeleteNetworkContainer failed with response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("DeleteNetworkContainer succeded with response %+v\n", resp)
	return nil
}

func getNetworkContainerByContext(t *testing.T, name string) error {
	var body bytes.Buffer
	var resp cns.GetNetworkContainerResponse

	podInfo := cns.KubernetesPodInfo{PodName: "testpod", PodNamespace: "testpodnamespace"}
	podInfoBytes, err := json.Marshal(podInfo)
	getReq := &cns.GetNetworkContainerRequest{OrchestratorContext: podInfoBytes}

	json.NewEncoder(&body).Encode(getReq)
	req, err := http.NewRequest(http.MethodPost, cns.GetNetworkContainerByOrchestratorContext, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	err = decodeResponse(w, &resp)
	if err != nil || resp.Response.ReturnCode != 0 {
		t.Errorf("GetNetworkContainerByContext failed with response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("**GetNetworkContainerByContext succeded with response %+v, raw:%+v\n", resp, w.Body)
	return nil
}

func getNonExistNetworkContainerByContext(t *testing.T, name string) error {
	var body bytes.Buffer
	var resp cns.GetNetworkContainerResponse

	podInfo := cns.KubernetesPodInfo{PodName: "testpod", PodNamespace: "testpodnamespace"}
	podInfoBytes, err := json.Marshal(podInfo)
	getReq := &cns.GetNetworkContainerRequest{OrchestratorContext: podInfoBytes}

	json.NewEncoder(&body).Encode(getReq)
	req, err := http.NewRequest(http.MethodPost, cns.GetNetworkContainerByOrchestratorContext, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	err = decodeResponse(w, &resp)
	if err != nil || resp.Response.ReturnCode != UnknownContainerID {
		t.Errorf("GetNetworkContainerByContext unexpected response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("**GetNonExistNetworkContainerByContext succeded with response %+v, raw:%+v\n", resp, w.Body)
	return nil
}

func getNetworkContainerStatus(t *testing.T, name string) error {
	var body bytes.Buffer
	var resp cns.GetNetworkContainerStatusResponse

	getReq := &cns.GetNetworkContainerStatusRequest{
		NetworkContainerid: "ethWebApp",
	}

	json.NewEncoder(&body).Encode(getReq)
	req, err := http.NewRequest(http.MethodPost, cns.GetNetworkContainerStatus, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	err = decodeResponse(w, &resp)
	if err != nil || resp.Response.ReturnCode != 0 {
		t.Errorf("GetNetworkContainerStatus failed with response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("**GetNetworkContainerStatus succeded with response %+v, raw:%+v\n", resp, w.Body)
	return nil
}

func getInterfaceForContainer(t *testing.T, name string) error {
	var body bytes.Buffer
	var resp cns.GetInterfaceForContainerResponse

	getReq := &cns.GetInterfaceForContainerRequest{
		NetworkContainerID: "ethWebApp",
	}

	json.NewEncoder(&body).Encode(getReq)
	req, err := http.NewRequest(http.MethodPost, cns.GetInterfaceForContainer, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	err = decodeResponse(w, &resp)
	if err != nil || resp.Response.ReturnCode != 0 {
		t.Errorf("GetInterfaceForContainer failed with response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("**GetInterfaceForContainer succeded with response %+v, raw:%+v\n", resp, w.Body)
	return nil
}

func TestSetOrchestratorType(t *testing.T) {
	fmt.Println("Test: TestSetOrchestratorType")

	setEnv(t)

	err := setOrchestratorType(t, cns.Kubernetes)
	if err != nil {
		t.Errorf("setOrchestratorType failed Err:%+v", err)
		t.Fatal(err)
	}
}

func TestCreateNetworkContainer(t *testing.T) {
	// requires more than 30 seconds to run
	fmt.Println("Test: TestCreateNetworkContainer")

	setEnv(t)
	setOrchestratorType(t, cns.ServiceFabric)

	orchestratorContext, _ := json.Marshal(
		cns.KubernetesPodInfo{PodName: "testpod", PodNamespace: "testpodnamespace"})

	// Setup NC: ethWebApp
	createNetworkContainerRequest := &cns.CreateNetworkContainerRequest{
		Version:                    "0.1",
		NetworkContainerid:         "ethWebApp",
		NetworkContainerType:       "WebApps",
		PrimaryInterfaceIdentifier: "11.0.0.7",
		OrchestratorContext:        orchestratorContext,
		IPConfiguration: cns.IPConfiguration{
			DNSServers:       []string{"8.8.8.8", "8.8.4.4"},
			GatewayIPAddress: "11.0.0.1",
			IPSubnet:         cns.IPSubnet{IPAddress: "11.0.0.5", PrefixLength: 24},
		},
	}

	if err := creatOrUpdateNetworkContainerWithName(t, createNetworkContainerRequest); err != nil {
		t.Errorf("creatOrUpdateNetworkContainerWithName failed with error: %v", err)
		t.Fatal(err)
	}

	// Setup NC: ethWebApp
	createNetworkContainerRequest = &cns.CreateNetworkContainerRequest{
		Version:                    "0.1",
		NetworkContainerid:         "ethWebApp",
		NetworkContainerType:       "WebApps",
		PrimaryInterfaceIdentifier: "11.0.0.7",
		OrchestratorContext:        orchestratorContext,
		IPConfiguration: cns.IPConfiguration{
			DNSServers:       []string{"8.8.8.8", "8.8.4.4"},
			GatewayIPAddress: "11.0.0.1",
			IPSubnet:         cns.IPSubnet{IPAddress: "11.0.0.6", PrefixLength: 24},
		},
	}

	if err := creatOrUpdateNetworkContainerWithName(t, createNetworkContainerRequest); err != nil {
		t.Errorf("Updating interface failed with error: %v", err)
	// Test create network container of type JobObject
	fmt.Println("TestCreateNetworkContainer: JobObject")
	err := creatOrUpdateNetworkContainerWithName(t, "testJobObject", "10.1.0.5", "JobObject")
	if err != nil {
		t.Errorf("Failed to save the goal state for network container of type JobObject "+
			" due to error: %+v", err)
		t.Fatal(err)
	}

	fmt.Println("Deleting the saved goal state for network container of type JobObject")
	err = deleteNetworkAdapterWithName(t, "testJobObject")
	if err != nil {
		t.Errorf("Failed to delete the saved goal state due to error: %+v", err)
		t.Fatal(err)
	}

	// Test create network container of type WebApps
	fmt.Println("TestCreateNetworkContainer: WebApps")
	err = creatOrUpdateNetworkContainerWithName(t, "ethWebApp", "192.0.0.5", "WebApps")
	if err != nil {
		t.Errorf("creatOrUpdateWebAppContainerWithName failed Err:%+v", err)
		t.Fatal(err)
	}

	err = creatOrUpdateNetworkContainerWithName(t, "ethWebApp", "192.0.0.6", "WebApps")
	if err != nil {
		t.Errorf("Updating interface failed Err:%+v", err)
		t.Fatal(err)
	}

	fmt.Println("Now calling DeleteNetworkContainer")

	if err := deleteNetworkContainerWithName(t, "ethWebApp"); err != nil {
		t.Errorf("Deleting interface failed Err:%+v", err)
		t.Fatal(err)
	}

	// Test create network container of type COW
	err = creatOrUpdateNetworkContainerWithName(t, "testCOWContainer", "10.0.0.5", "COW")
	if err != nil {
		t.Errorf("Failed to save the goal state for network container of type COW"+
			" due to error: %+v", err)
		t.Fatal(err)
	}

	fmt.Println("Deleting the saved goal state for network container of type COW")
	err = deleteNetworkAdapterWithName(t, "testCOWContainer")
	if err != nil {
		t.Errorf("Failed to delete the saved goal state due to error: %+v", err)
		t.Fatal(err)
	}

}

func TestGetNetworkContainerByOrchestratorContext(t *testing.T) {
	// requires more than 30 seconds to run
	fmt.Println("Test: TestGetNetworkContainerByOrchestratorContext")

	setEnv(t)
	setOrchestratorType(t, cns.Kubernetes)

	// Setup NC: ethWebApp
	orchestratorContext, _ := json.Marshal(
		cns.KubernetesPodInfo{PodName: "testpod", PodNamespace: "testpodnamespace"})

	createNetworkContainerRequest := &cns.CreateNetworkContainerRequest{
		Version:                    "0.1",
		NetworkContainerid:         "ethWebApp",
		NetworkContainerType:       "AzureContainerInstance",
		PrimaryInterfaceIdentifier: "11.0.0.7",
		OrchestratorContext:        orchestratorContext,
		IPConfiguration: cns.IPConfiguration{
			DNSServers:       []string{"8.8.8.8", "8.8.4.4"},
			GatewayIPAddress: "11.0.0.1",
			IPSubnet:         cns.IPSubnet{IPAddress: "11.0.0.5", PrefixLength: 24},
		},
	}

	if err := creatOrUpdateNetworkContainerWithName(t, createNetworkContainerRequest); err != nil {
		t.Errorf("Updating interface failed with error: %v", err)
		t.Fatal(err)
	}

	fmt.Println("Now calling getNetworkContainerStatus")
	err = getNetworkContainerByContext(t, "ethWebApp")
	if err != nil {
		t.Errorf("TestGetNetworkContainerByOrchestratorContext failed Err:%+v", err)
		t.Fatal(err)
	}

	fmt.Println("Now calling DeleteNetworkContainer")

	if err := deleteNetworkContainerWithName(t, "ethWebApp"); err != nil {
		t.Errorf("Deleting interface failed Err:%+v", err)
		t.Fatal(err)
	}

	err = getNonExistNetworkContainerByContext(t, "ethWebApp")
	if err != nil {
		t.Errorf("TestGetNetworkContainerByOrchestratorContext failed Err:%+v", err)
		t.Fatal(err)
	}
}

func TestGetNetworkContainerStatus(t *testing.T) {
	// requires more than 30 seconds to run
	fmt.Println("Test: TestCreateNetworkContainer")

	setEnv(t)

	// Setup NC: ethWebApp
	orchestratorContext, _ := json.Marshal(
		cns.KubernetesPodInfo{PodName: "testpod", PodNamespace: "testpodnamespace"})

	createNetworkContainerRequest := &cns.CreateNetworkContainerRequest{
		Version:                    "0.1",
		NetworkContainerid:         "ethWebApp",
		NetworkContainerType:       "WebApps",
		PrimaryInterfaceIdentifier: "11.0.0.7",
		OrchestratorContext:        orchestratorContext,
		IPConfiguration: cns.IPConfiguration{
			DNSServers:       []string{"8.8.8.8", "8.8.4.4"},
			GatewayIPAddress: "11.0.0.1",
			IPSubnet:         cns.IPSubnet{IPAddress: "11.0.0.5", PrefixLength: 24},
		},
	}

	if err := creatOrUpdateNetworkContainerWithName(t, createNetworkContainerRequest); err != nil {
		t.Errorf("creatOrUpdateNetworkContainerWithName failed with error: %v", err)
		t.Fatal(err)
	}

	fmt.Println("Now calling getNetworkContainerStatus")
	err = getNetworkContainerStatus(t, "ethWebApp")
	if err != nil {
		t.Errorf("getNetworkContainerStatus failed Err:%+v", err)
		t.Fatal(err)
	}

	fmt.Println("Now calling DeleteNetworkContainer")

	if err := deleteNetworkContainerWithName(t, "ethWebApp"); err != nil {
		t.Errorf("Deleting interface failed Err:%+v", err)
		t.Fatal(err)
	}
}

func TestGetInterfaceForNetworkContainer(t *testing.T) {
	// requires more than 30 seconds to run
	fmt.Println("Test: TestCreateNetworkContainer")

	setEnv(t)

	// Setup NC: ethWebApp
	orchestratorContext, _ := json.Marshal(
		cns.KubernetesPodInfo{PodName: "testpod", PodNamespace: "testpodnamespace"})

	createNetworkContainerRequest := &cns.CreateNetworkContainerRequest{
		Version:                    "0.1",
		NetworkContainerid:         "ethWebApp",
		NetworkContainerType:       "WebApps",
		PrimaryInterfaceIdentifier: "11.0.0.7",
		OrchestratorContext:        orchestratorContext,
		IPConfiguration: cns.IPConfiguration{
			DNSServers:       []string{"8.8.8.8", "8.8.4.4"},
			GatewayIPAddress: "11.0.0.1",
			IPSubnet:         cns.IPSubnet{IPAddress: "11.0.0.5", PrefixLength: 24},
		},
	}

	if err := creatOrUpdateNetworkContainerWithName(t, createNetworkContainerRequest); err != nil {
		t.Errorf("creatOrUpdateNetworkContainerWithName failed with error: %v", err)
		t.Fatal(err)
	}

	fmt.Println("Now calling getInterfaceForContainer")
	if err := getInterfaceForContainer(t, "ethWebApp"); err != nil {
		t.Errorf("getInterfaceForContainer failed Err:%+v", err)
		t.Fatal(err)
	}

	fmt.Println("Now calling DeleteNetworkContainer")

	if err := deleteNetworkContainerWithName(t, "ethWebApp"); err != nil {
		t.Errorf("Deleting interface failed Err:%+v", err)
		t.Fatal(err)
	}
}

func TestGetNumOfCPUCores(t *testing.T) {
	fmt.Println("Test: getNumberOfCPUCores")

	var (
		err error
		req *http.Request
	)

	req, err = http.NewRequest(http.MethodGet, cns.NumberOfCPUCoresPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	var w *httptest.ResponseRecorder
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var numOfCoresResponse cns.NumOfCPUCoresResponse

	err = decodeResponse(w, &numOfCoresResponse)
	if err != nil || numOfCoresResponse.Response.ReturnCode != 0 {
		t.Errorf("getNumberOfCPUCores failed with response %+v", numOfCoresResponse)
	} else {
		fmt.Printf("getNumberOfCPUCores Responded with %+v\n", numOfCoresResponse)
	}
}

func TestCompartmentWithNCs(t *testing.T) {
	fmt.Println("Test: TestCompartmentWithNCs")

	if "windows" != platform.GetOSInfo() {
		errInfo := fmt.Errorf("TestCompartmentWithNCs is windows specific test")
		t.Errorf(errInfo.Error())
		t.Fatal(errInfo)
	}

	setEnv(t)
	setOrchestratorType(t, cns.Kubernetes)

	// setup 3 NCs for this test
	// Get the primary interface IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		t.Errorf("Failed to get the primary interface IP due to error: %v", err)
		t.Fatal(err)
	}

	defer conn.Close()
	primaryInterfaceIP := strings.Split(conn.LocalAddr().(*net.UDPAddr).String(), ":")[0]

	// Setup NC: Swift_170e7a01-a4da-4851-cea5-08589a449645
	createNetworkContainerRequest := &cns.CreateNetworkContainerRequest{
		Version:                    "0.1",
		NetworkContainerid:         "Swift_170e7a01-a4da-4851-cea5-08589a449645",
		NetworkContainerType:       "JobObject",
		PrimaryInterfaceIdentifier: primaryInterfaceIP,
		IPConfiguration: cns.IPConfiguration{
			DNSServers:       []string{"192.168.0.66", "192.168.0.67"},
			GatewayIPAddress: "192.168.0.65",
			IPSubnet:         cns.IPSubnet{IPAddress: "192.168.0.70", PrefixLength: 26},
		},
		MultiTenancyInfo: cns.MultiTenancyInfo{EncapType: "Vlan", ID: 2},
	}

	if err := creatOrUpdateNetworkContainerWithName(t, createNetworkContainerRequest); err != nil {
		t.Errorf("creatOrUpdateNetworkContainerWithName failed with error: %v", err)
		t.Fatal(err)
	}

	// Setup NC: Swift_171e7a01-a4da-4851-cea5-08589a449645
	createNetworkContainerRequest = &cns.CreateNetworkContainerRequest{
		Version:                    "0.1",
		NetworkContainerid:         "Swift_171e7a01-a4da-4851-cea5-08589a449645",
		NetworkContainerType:       "JobObject",
		PrimaryInterfaceIdentifier: primaryInterfaceIP,
		IPConfiguration: cns.IPConfiguration{
			DNSServers:       []string{"192.168.0.66", "192.168.0.67"},
			GatewayIPAddress: "192.168.0.65",
			IPSubnet:         cns.IPSubnet{IPAddress: "192.168.0.71", PrefixLength: 26},
		},
		MultiTenancyInfo: cns.MultiTenancyInfo{EncapType: "Vlan", ID: 3},
	}

	if err := creatOrUpdateNetworkContainerWithName(t, createNetworkContainerRequest); err != nil {
		t.Errorf("creatOrUpdateNetworkContainerWithName failed with error: %v", err)
		t.Fatal(err)
	}

	// Setup NC: Swift_180e7a01-a4da-4851-cea5-08589a449645
	createNetworkContainerRequest = &cns.CreateNetworkContainerRequest{
		Version:                    "0.1",
		NetworkContainerid:         "Swift_180e7a01-a4da-4851-cea5-08589a449645",
		NetworkContainerType:       "JobObject",
		PrimaryInterfaceIdentifier: primaryInterfaceIP,
		IPConfiguration: cns.IPConfiguration{
			DNSServers:       []string{"192.168.0.66", "192.168.0.67"},
			GatewayIPAddress: "192.168.0.65",
			IPSubnet:         cns.IPSubnet{IPAddress: "192.168.0.80", PrefixLength: 26},
		},
		MultiTenancyInfo: cns.MultiTenancyInfo{EncapType: "Vlan", ID: 4},
	}

	if err := creatOrUpdateNetworkContainerWithName(t, createNetworkContainerRequest); err != nil {
		t.Errorf("creatOrUpdateNetworkContainerWithName failed with error: %v", err)
		t.Fatal(err)
	}

	defer func() {
		// Remove the network containers
		deleteNetworkContainerWithName(t, "Swift_170e7a01-a4da-4851-cea5-08589a449645")
		deleteNetworkContainerWithName(t, "Swift_171e7a01-a4da-4851-cea5-08589a449645")
		deleteNetworkContainerWithName(t, "Swift_180e7a01-a4da-4851-cea5-08589a449645")
	}()

	createCompartmentWithValidNCIDs(t)
	createCompartmentWithInvalidNCIDs(t)
	createCompartmentWithNCsTestMaxNCCount(t)
	createCompartmentWithDuplicateNCIDs(t)

	deleteInvalidCompartments(t)
}

func deleteInvalidCompartments(t *testing.T) {
	invalidCompartmentIDs := []int{0, 1, 100}

	for _, invalidCompartmentID := range invalidCompartmentIDs {
		fmt.Printf("deleteInvalidCompartment for compartmentID %d\n", invalidCompartmentID)

		reqInfo := cns.DeleteCompartmentWithNCsRequest{
			CompartmentID: invalidCompartmentID,
		}

		var (
			body bytes.Buffer
			resp cns.Response
		)

		json.NewEncoder(&body).Encode(reqInfo)
		reqPost, err := http.NewRequest(http.MethodDelete, cns.DeleteCompartmentWithNCs, &body)
		if err != nil {
			t.Fatal(err)
		}

		w := httptest.NewRecorder()
		mux.ServeHTTP(w, reqPost)

		err = decodeResponse(w, &resp)
		if err != nil || resp.ReturnCode != InvalidParameter {
			t.Errorf("deleteInvalidCompartment unexpected response %+v Err: %+v", resp, err)
			t.Fatal(err)
		}

		fmt.Printf("deleteInvalidCompartment succeded with response %+v, raw: %+v\n", resp, w.Body)
	}
}

func deleteCompartmentWithNCs(t *testing.T, compartmentID int) {
	fmt.Printf("deleteCompartmentWithNCs for compartmentID %d\n", compartmentID)

	reqInfo := cns.DeleteCompartmentWithNCsRequest{
		CompartmentID: compartmentID,
	}

	var (
		body bytes.Buffer
		resp cns.Response
	)

	json.NewEncoder(&body).Encode(reqInfo)
	reqPost, err := http.NewRequest(http.MethodDelete, cns.DeleteCompartmentWithNCs, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, reqPost)

	err = decodeResponse(w, &resp)
	if err != nil || resp.ReturnCode != Success {
		t.Errorf("DeleteCompartmentWithNCs unexpected response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("DeleteCompartmentWithNCs succeded with response %+v, raw:%+v\n", resp, w.Body)
	return
}

func createCompartmentWithInvalidNCIDs(t *testing.T) {
	fmt.Printf("createCompartmentWithInvalidNCIDs:\n" +
		"Swift_170e7a01-a4da-4851-cea5-08589a449645\nSwift_180e7a01-a4da-4851-cea5-08589a449645")

	ncIDs := []string{"170e7a01-a4da-4851-cea5-08589a449645", "1801e7a01-a4da-4851-cea5-08589a449645"}
	reqInfo := cns.CreateCompartmentWithNCsRequest{
		NCIDs: ncIDs,
	}

	var (
		body bytes.Buffer
		resp cns.CreateCompartmentWithNCsResponse
	)

	json.NewEncoder(&body).Encode(reqInfo)
	reqPost, err := http.NewRequest(http.MethodPost, cns.CreateCompartmentWithNCs, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, reqPost)

	err = decodeResponse(w, &resp)
	if err != nil || resp.Response.ReturnCode != InvalidParameter {
		t.Errorf("CreateCompartmentWithNCs unexpected response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("CreateCompartmentWithNCs succeded with response %+v, raw:%+v\n", resp, w.Body)
	return
}

func createCompartmentWithValidNCIDs(t *testing.T) {
	fmt.Printf("createCompartmentWithValidNCIDs:\n" +
		"Swift_170e7a01-a4da-4851-cea5-08589a449645\nSwift_171e7a01-a4da-4851-cea5-08589a449645\n")

	ncIDs := []string{"170e7a01-a4da-4851-cea5-08589a449645", "171e7a01-a4da-4851-cea5-08589a449645"}
	reqInfo := cns.CreateCompartmentWithNCsRequest{
		NCIDs: ncIDs,
	}

	var body bytes.Buffer
	var resp cns.CreateCompartmentWithNCsResponse

	json.NewEncoder(&body).Encode(reqInfo)
	reqPost, err := http.NewRequest(http.MethodPost, cns.CreateCompartmentWithNCs, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, reqPost)

	err = decodeResponse(w, &resp)
	if err != nil || resp.Response.ReturnCode != 0 {
		t.Errorf("CreateCompartmentWithNCs unexpected response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("CreateCompartmentWithNCs succeded with response %+v, raw:%+v\n", resp, w.Body)

	deleteCompartmentWithNCs(t, resp.CompartmentID)
}

func createCompartmentWithNCsTestMaxNCCount(t *testing.T) {
	fmt.Printf("CreateCompartmentWithNCs:\n" +
		"Swift_170e7a01-a4da-4851-cea5-08589a449645\nSwift_171e7a01-a4da-4851-cea5-08589a449645" +
		"\nSwift_172e7a01-a4da-4851-cea5-08589a449645\n")

	ncIDs := []string{"170e7a01-a4da-4851-cea5-08589a449645",
		"171e7a01-a4da-4851-cea5-08589a449645", "Swift_172e7a01-a4da-4851-cea5-08589a449645"}
	reqInfo := cns.CreateCompartmentWithNCsRequest{
		NCIDs: ncIDs,
	}

	var body bytes.Buffer
	var resp cns.CreateCompartmentWithNCsResponse

	json.NewEncoder(&body).Encode(reqInfo)
	reqPost, err := http.NewRequest(http.MethodPost, cns.CreateCompartmentWithNCs, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, reqPost)

	err = decodeResponse(w, &resp)
	if err != nil || resp.Response.ReturnCode != InvalidParameter {
		t.Errorf("CreateCompartmentWithNCs unexpected response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("CreateCompartmentWithNCs succeded with response %+v, raw:%+v\n", resp, w.Body)
	return
}

func createCompartmentWithDuplicateNCIDs(t *testing.T) {
	fmt.Printf("createCompartmentWithDuplicateNCIDs:\n" +
		"Swift_170e7a01-a4da-4851-cea5-08589a449645\nSwift_170e7a01-a4da-4851-cea5-08589a449645")

	ncIDs := []string{"170e7a01-a4da-4851-cea5-08589a449645", "170e7a01-a4da-4851-cea5-08589a449645"}
	reqInfo := cns.CreateCompartmentWithNCsRequest{
		NCIDs: ncIDs,
	}

	var body bytes.Buffer
	var resp cns.CreateCompartmentWithNCsResponse

	json.NewEncoder(&body).Encode(reqInfo)
	reqPost, err := http.NewRequest(http.MethodPost, cns.CreateCompartmentWithNCs, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, reqPost)

	err = decodeResponse(w, &resp)
	if err != nil || resp.Response.ReturnCode != UnexpectedError {
		t.Errorf("CreateCompartmentWithNCs unexpected response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("CreateCompartmentWithNCs succeded with response %+v, raw:%+v\n", resp, w.Body)
	return
}

func deleteNetworkContainerWithName(t *testing.T, name string) error {
	var body bytes.Buffer
	info := &cns.DeleteNetworkContainerRequest{
		NetworkContainerid: name,
	}

	json.NewEncoder(&body).Encode(info)

	req, err := http.NewRequest(http.MethodPost, cns.DeleteNetworkContainer, &body)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var resp cns.DeleteNetworkContainerResponse
	err = decodeResponse(w, &resp)

	if err != nil || resp.Response.ReturnCode != Success {
		t.Errorf("DeleteNetworkContainerRequest failed with response %+v Err:%+v", resp, err)
		t.Fatal(err)
	}

	fmt.Printf("DeleteNetworkContainerRequest succeeded with response %+v\n", resp)

	return nil
}
