package secureagent

import (
	"fmt"
	"log"
	"os"
	"strings"
)

const unitFile = "sztp-agent.service"

func CreateUnitFile(execOptions string, path string) error {
	path = strings.TrimSuffix(path, "/") + "/" + unitFile // ensures no double trailing slashes
	contents := fmt.Sprintf(`[Unit]
Description=SZTP Agent
After=network.target

[Service]
ExecStart=opi-sztp-agent %[1]s
ExecReload=opi-sztp-agent %[1]s
Type=notify
Restart=always

[Install]
WantedBy=default.target
RequiredBy=network.target
`, execOptions)

	err := os.WriteFile(path, []byte(contents), 0644)
	if err != nil {
		return fmt.Errorf("creating unit file %s: %v", path, err)
	}

	log.Printf("Unit file %s created successfully. Ensure sztp-agent binary is installed on your system", path+"")
	return nil
}
