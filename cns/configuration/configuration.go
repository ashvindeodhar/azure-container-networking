// Copyright Microsoft. All rights reserved.
package configuration

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/Azure/azure-container-networking/cns/logger"
	"github.com/Azure/azure-container-networking/common"
)

const (
	defaultConfigName = "cns_config.json"
)

type CNSConfig struct {
	TelemetrySettings TelemetrySettings
}

type TelemetrySettings struct {
	// Flag to disable the telemetry.
	DisableAll bool
	// Flag to Disable sending trace.
	DisableTrace bool
	// Flag to Disable sending metric.
	DisableMetric bool
	// Configure how many bytes can be sent in one call to the data collector
	TelemetryBatchSizeBytes int
	// Configure the maximum delay before sending queued telemetry in milliseconds
	TelemetryBatchIntervalInSecs int
	// Heartbeat interval for sending heartbeat metric
	HeartBeatIntervalInMins int
	// Enable thread for getting metadata from wireserver
	DisableMetadataRefreshThread bool
	// Refresh interval in milliseconds for metadata thread
	RefreshIntervalInSecs int
	// Disable debug logging for telemetry messages
	DebugMode bool
}

// This functions reads cns config file and save it in a structure
func ReadConfig() (CNSConfig, error) {
	var cnsConfig CNSConfig

	// Check if env set for config path otherwise use default path
	configpath, found := os.LookupEnv("CNS_CONFIGURATION_PATH")
	if !found {
		dir, err := common.GetExecutableDirectory()
		if err != nil {
			logger.Errorf("[Configuration] Failed to find exe dir:%v", err)
			return cnsConfig, err
		}

		configpath = filepath.Join(dir, defaultConfigName)
		//dir + string(os.PathSeparator) + defaultConfigName
	}

	logger.Printf("Config path:%s", configpath)

	content, err := ioutil.ReadFile(configpath)
	if err != nil {
		logger.Errorf("[Configuration] Failed to read config file :%v", err)
		return cnsConfig, err
	}

	err = json.Unmarshal(content, &cnsConfig)
	return cnsConfig, err
}

// set telmetry setting defaults
func setTelemetrySettingDefaults(telemetrySettings *TelemetrySettings) {
	if telemetrySettings.RefreshIntervalInSecs == 0 {
		// set the default refresh interval of metadata thread to 15 seconds
		telemetrySettings.RefreshIntervalInSecs = 15
	}

	if telemetrySettings.TelemetryBatchIntervalInSecs == 0 {
		// set the default AI telemetry batch interval to 30 seconds
		telemetrySettings.TelemetryBatchIntervalInSecs = 30
	}

	if telemetrySettings.TelemetryBatchSizeBytes == 0 {
		// set the default AI telemetry batch size to 32768 bytes
		telemetrySettings.TelemetryBatchSizeBytes = 32768
	}

	if telemetrySettings.HeartBeatIntervalInMins == 0 {
		// set the default Heartbeat interval to 30 minutes
		telemetrySettings.HeartBeatIntervalInMins = 30
	}
}

// Set Default values of CNS config if not specified
func SetCNSConfigDefaults(config *CNSConfig) {
	setTelemetrySettingDefaults(&config.TelemetrySettings)
}
