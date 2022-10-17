package secureAgent

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Auxiliar function to get lines from file matching with the substr
func linesInFileContains(file string, substr string) string {
	f, _ := os.Open(file)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, substr) {
			return line
		}
	}
	return ""
}

func extractfromLine(line, regex string, index int) string {
	re := regexp.MustCompile(regex)
	res := re.FindAllString(line, -1)
	if len(res) == 1 {
		return ""
	}
	return re.FindAllString(line, -1)[index]
}

func (a *Agent) doTLSRequest(input string, url string) (*BootstrapServerPostOutput, error) {

	var postResponse BootstrapServerPostOutput

	body := strings.NewReader(input)
	r, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}

	r.SetBasicAuth(a.GetSerialNumber(), a.GetDevicePassword())
	r.Header.Add("Content-Type", a.GetContentTypeReq())

	caCert, _ := ioutil.ReadFile(a.GetBootstrapTrustAnchorCert())
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cert, _ := tls.LoadX509KeyPair(a.GetDeviceEndEntityCert(), a.GetDevicePrivateKey())

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	//TODO remove sleep later
	time.Sleep(20 * time.Second)
	res, err := client.Do(r)
	if err != nil {
		log.Println("Error doing the request", err.Error())
		return nil, err
	}

	derr := json.NewDecoder(res.Body).Decode(&postResponse)
	if derr != nil {
		return nil, derr
	}
	log.Println(postResponse)
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("[ERROR] Status code received: " + strconv.Itoa(res.StatusCode) + " ...but status code expected: " + strconv.Itoa(http.StatusOK))
	}
	defer res.Body.Close()
	return &postResponse, nil
}

func generateInputJSONContent() string {
	osName := replaceQuotes(strings.Split(linesInFileContains(OS_RELEASE_FILE, "NAME"), "=")[1])
	osVersion := replaceQuotes(strings.Split(linesInFileContains(OS_RELEASE_FILE, "VERSION"), "=")[1])

	//dmidecode.Dmidecode(true))  //This is one possibility to get hw information

	input := &InputJSON{
		IetfSztpBootstrapServerInput: struct {
			HwModel   string `json:"hw-model"`
			OsName    string `json:"os-name"`
			OsVersion string `json:"os-version"`
			Nonce     string `json:"nonce"`
		}{
			HwModel:   "hardwared-model-TBD",
			OsName:    osName,
			OsVersion: osVersion,
			Nonce:     "",
		},
	}
	inputJson, _ := json.Marshal(input)
	return string(inputJson)
}

func replaceQuotes(input string) string {
	return strings.ReplaceAll(input, "\"", "")
}
