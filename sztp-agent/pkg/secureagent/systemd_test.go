package secureagent

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func TestCreateUnitFile(t *testing.T) {
	const testOptions = "-bogus -options"
	const unitFilePath = "/tmp"

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
`, testOptions)

	CreateUnitFile(testOptions, unitFilePath)

	b, err := os.ReadFile(unitFilePath + "/" + unitFile)
	if err != nil {
		t.Errorf("Error reading unit file %s: %v", unitFilePath, err)
	}

	if !bytes.Equal(b, []byte(contents)) {
		t.Errorf("Bytes do not match for contents and written unit file %s", unitFilePath)
	}

	err = os.Remove(unitFilePath + "/" + unitFile)
	if err != nil {
		t.Errorf("Error deleting unit file %s: %v", unitFilePath, err)
	}
}
