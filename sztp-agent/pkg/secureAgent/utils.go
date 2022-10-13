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
)

//Auxiliar function to get lines from file matching with the substr
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
	return re.FindAllString(line, -1)[index]
}

func (a *Agent) doTLSRequestToBootstrap() (*BootstrapServerPostOutput, error) {

	body := strings.NewReader(a.GetInputJSONContent())
	log.Println(a.GetInputJSONContent())
	r, err := http.NewRequest(http.MethodPost, a.GetBootstrapURL(), body)
	if err != nil {
		panic(err)
	}

	log.Println(a.GetSerialNumber(), a.GetDevicePassword())
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
	log.Println(r)
	res, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	post := &BootstrapServerPostOutput{}
	derr := json.NewDecoder(res.Body).Decode(post)
	if derr != nil {
		return nil, derr
	}
	log.Println(res.Status)
	if res.StatusCode != http.StatusCreated {
		return nil, errors.New("[ERROR] Status code received: " + strconv.Itoa(res.StatusCode) + " ...but status code expected: " + strconv.Itoa(http.StatusCreated))
	}
	return post, nil
}

func generateInputJSONContent() string {
	osName := replaceQuotes(strings.Split(linesInFileContains(OS_RELEASE_FILE, "NAME"), "=")[1])
	osVersion := replaceQuotes(strings.Split(linesInFileContains(OS_RELEASE_FILE, "VERSION"), "=")[1])

	//dmidecode.Dmidecode(true))  //This is one possibility to get hw information

	input := &InputJSON{
		IetfSztpBootstrapServerInput: struct {
			HwModel             string        `json:"hw-model"`
			OsName              string        `json:"os-name"`
			OsVersion           string        `json:"os-version"`
			SignedDataPreferred []interface{} `json:"signed-data-preferred"`
			Nonce               string        `json:"nonce"`
		}{
			HwModel:             "hardwared-model-TBD",
			OsName:              osName,
			OsVersion:           osVersion,
			SignedDataPreferred: nil,
			Nonce:               "",
		},
	}
	inputJson, _ := json.Marshal(input)
	return string(inputJson)
}

func replaceQuotes(input string) string {
	return strings.ReplaceAll(input, "\"", "")
}
