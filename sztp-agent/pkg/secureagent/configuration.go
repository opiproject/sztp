package secureagent

import (
	"encoding/base64"
	"log"
	"os"
	"os/exec"
)

func (a *Agent) copyConfigurationFile() error {
	log.Println("[INFO] Starting the Copy Configuration.")
	_ = a.doReportProgress(ProgressTypeConfigInitiated, "Configuration Initiated")
	_ = a.UpdateAndSaveStatus("config", true, "")
	// Copy the configuration file to the device
	file, err := os.Create(ARTIFACTS_PATH + a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference + "-config")
	if err != nil {
		log.Println("[ERROR] creating the configuration file", err.Error())
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Println("[ERROR] Error when closing:", err)
		}
	}()

	plainTest, _ := base64.StdEncoding.DecodeString(a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.Configuration)
	_, err = file.WriteString(string(plainTest))
	if err != nil {
		log.Println("[ERROR] writing the configuration file", err.Error())
		return err
	}
	// nolint:gosec
	err = os.Chmod(ARTIFACTS_PATH+a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference+"-config", 0744)
	if err != nil {
		log.Println("[ERROR] changing the configuration file permission", err.Error())
		return err
	}
	log.Println("[INFO] Configuration file copied successfully")
	_ = a.doReportProgress(ProgressTypeConfigComplete, "Configuration Complete")
	_ = a.UpdateAndSaveStatus("config", false, "")
	return nil
}

func (a *Agent) launchScriptsConfiguration(typeOf string) error {
	var script, scriptName string
	var reportStart, reportEnd ProgressType
	switch typeOf {
	case "post":
		script = a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.PostConfigurationScript
		scriptName = "post"
		reportStart = ProgressTypePostScriptInitiated
		reportEnd = ProgressTypePostScriptComplete
	default: // pre or default
		script = a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.PreConfigurationScript
		scriptName = "pre"
		reportStart = ProgressTypePreScriptInitiated
		reportEnd = ProgressTypePreScriptComplete
	}
	log.Println("[INFO] Starting the " + scriptName + "-configuration.")
	_ = a.doReportProgress(reportStart, "Report starting")
	_ = a.UpdateAndSaveStatus(scriptName+"-script", true, "")
	// nolint:gosec
	file, err := os.Create(ARTIFACTS_PATH + a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference + scriptName + "configuration.sh")
	if err != nil {
		log.Println("[ERROR] creating the "+scriptName+"-configuration script", err.Error())
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Println("[ERROR] Error when closing:", err)
		}
	}()

	plainTest, _ := base64.StdEncoding.DecodeString(script)
	_, err = file.WriteString(string(plainTest))
	if err != nil {
		log.Println("[ERROR] writing the "+scriptName+"-configuration script", err.Error())
		return err
	}
	// nolint:gosec
	err = os.Chmod(ARTIFACTS_PATH+a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference+scriptName+"configuration.sh", 0755)
	if err != nil {
		log.Println("[ERROR] changing the "+scriptName+"-configuration script permission", err.Error())
		return err
	}
	log.Println("[INFO] " + scriptName + "-configuration script created successfully")
	cmd := exec.Command("/bin/sh", ARTIFACTS_PATH+a.BootstrapServerOnboardingInfo.IetfSztpConveyedInfoOnboardingInformation.InfoTimestampReference+scriptName+"configuration.sh") //nolint:gosec
	out, err := cmd.Output()
	if err != nil {
		log.Println("[ERROR] running the "+scriptName+"-configuration script", err.Error())
		return err
	}
	log.Println(string(out)) // remove it
	_ = a.doReportProgress(reportEnd, "Report end")
	_ = a.UpdateAndSaveStatus(scriptName+"-script", false, "")
	log.Println("[INFO] " + scriptName + "-Configuration script executed successfully")
	return nil
}
