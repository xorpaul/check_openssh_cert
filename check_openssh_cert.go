package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/ssh"

	nagios "github.com/xorpaul/go-nagios"
	H "github.com/xorpaul/gohelper"
)

var (
	sslSkipVerify bool
	debug         bool
	verbose       bool
	info          bool
	quiet         bool
	buildtime     string
	client        *http.Client
)

type response struct {
	CertificateAuthority string `json:"ca"`
	Certificate          string `json:"cert"`
}

func setupHttpClient() *http.Client {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Trust the augmented cert pool in our client
	tlsConfig := &tls.Config{
		RootCAs: rootCAs,
	}
	if sslSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	tr := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: tr}
}

func doRequest(url string) []byte {
	H.Debugf("sending request to " + string(url))
	resp, err := client.Get(url)
	//H.Debugf("sending HTTP request " + url)
	if err != nil {
		H.Fatalf("Error while issuing request to " + url + " Error: " + err.Error())
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		H.Fatalf("Error while reading response body: " + err.Error())
	}
	H.Debugf("Received response: " + string(body))

	return body
}

func main() {
	log.SetOutput(os.Stdout)

	var (
		urlFlag                      = flag.String("url", "https://127.0.0.1/check", "which URL to send the GET to to get the certificate")
		versionFlag                  = flag.Bool("version", false, "show build time and version number")
		verifyAgainstSignatureShaSum = flag.String("verifyAgainstSignatureShaSum", "", "file location to check the recieved certificat's signature against")
	)
	flag.BoolVar(&debug, "debug", false, "log debug output, defaults to false")
	flag.BoolVar(&sslSkipVerify, "sslSkipVerify", false, "add InsecureSkipVerify: true to the http client for invalid certificates")
	flag.Parse()

	version := *versionFlag
	url := *urlFlag

	if version {
		fmt.Println("check_openssh_cert version 0.0.1 Build time:", buildtime, "UTC")
		os.Exit(0)
	}

	H.Info = false
	H.Debug = debug
	H.InfoTimestamp = true
	H.WarnExit = true

	if len(*verifyAgainstSignatureShaSum) < 1 {
		H.Fatalf("Error: Parameter -verifyAgainstSignatureShaSum needs to be set to the SHA256 sum of the recieved certificate's signature, e.g.  SHA256:Ar7bYZIf/BvWbwkFEukZgjK8lRpzvsvbjGbZ9SwWshE")
	}

	client = setupHttpClient()
	body := doRequest(url)
	var response response
	err := json.Unmarshal(body, &response)
	if err != nil {
		H.Warnf("Could not parse JSON response: " + string(body) + " Error: " + err.Error())
	}
	H.Infof("Received valid response from " + url)

	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.Certificate))
	if err != nil {
		H.Fatalf("Error while parsing OpenSSH authorized key from " + url + " Error: " + err.Error())
	}
	cert := k.(*ssh.Certificate)
	//log.Printf("%#v", cert)

	nr := nagios.NagiosResult{}
	if *verifyAgainstSignatureShaSum == ssh.FingerprintSHA256(cert.SignatureKey) {
		nr.ExitCode = 0
		nr.Text = "Received certificate's signature from " + url + " matched the given sha256 fingerprint " + *verifyAgainstSignatureShaSum
		nagios.NagiosExit(nr)
	} else {
		nr.ExitCode = 1
		nr.Text = "Received certificate's signature from " + url + " did not match the given sha256 fingerprint " + *verifyAgainstSignatureShaSum
		nagios.NagiosExit(nr)
	}

}
