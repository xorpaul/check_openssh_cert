package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/tidwall/gjson"
	nagios "github.com/xorpaul/go-nagios"
	H "github.com/xorpaul/gohelper"
	"golang.org/x/crypto/ssh"
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

func setupHTTPClient() *http.Client {
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

func doRequest(url string) string {
	H.Debugf("sending request to " + string(url))
	resp, err := client.Get(url)
	//H.Debugf("sending HTTP request " + url)
	if err != nil {
		H.Fatalf("Error while issuing request to " + url + " Error: " + err.Error())
	}
	defer resp.Body.Close()
	byteBody, err := ioutil.ReadAll(resp.Body)
	body := string(byteBody)
	if err != nil {
		H.Fatalf("Error while reading response body: " + err.Error())
	}
	H.Debugf("Received response: " + body)

	return body
}

func main() {
	log.SetOutput(os.Stdout)

	var (
		urlFlag                      = flag.String("url", "https://127.0.0.1:443/check", "which URL to send the GET to to get the certificate")
		versionFlag                  = flag.Bool("version", false, "show build time and version number")
		jsonKey                      = flag.String("jsonKey", "certificate", "JSON key which contains the Authorized Key")
		receivedCertficiateIsCA      = flag.Bool("receivedCertficiateIsCA", false, "the certificate received from the url is a CA, if this is false then a end certificate is expected")
		verifyAgainstSignatureShaSum = flag.String("verifyAgainstSignatureShaSum", "", "sha256 sum of the received certificate's fingerprint")
	)
	flag.BoolVar(&debug, "debug", false, "log debug output, defaults to false")
	flag.BoolVar(&sslSkipVerify, "sslSkipVerify", false, "add InsecureSkipVerify: true to the http client for invalid certificates")
	flag.Parse()

	version := *versionFlag
	url := *urlFlag

	if version {
		fmt.Println("check_openssh_cert version 0.0.2 Build time:", buildtime, "UTC")
		os.Exit(0)
	}

	H.Info = false
	H.Debug = debug
	H.InfoTimestamp = true
	H.WarnExit = true

	if len(*verifyAgainstSignatureShaSum) < 1 {
		H.Fatalf("Error: Parameter -verifyAgainstSignatureShaSum needs to be set to the SHA256 sum of the recieved certificate's signature, e.g.  SHA256:Ar7bYZIf/BvWbwkFEukZgjK8lRpzvsvbjGbZ9SwWshE")
	}

	client = setupHTTPClient()
	body := doRequest(url)
	certificateInAuthorizedKeyFormat := gjson.Get(body, *jsonKey).String()
	if len(certificateInAuthorizedKeyFormat) < 1 {
		H.Warnf("Could not find specified JSON key: '" + *jsonKey + "' in response: " + body)
	}
	//log.Printf(certificateInAuthorizedKeyFormat)
	//log.Printf("%#v", response)
	H.Infof("Received valid response from " + url)

	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certificateInAuthorizedKeyFormat))
	if err != nil {
		H.Fatalf("Error while parsing OpenSSH authorized key from " + url + " Error: " + err.Error())
	}
	//log.Printf("%#v", k)

	publicKey := k
	if !*receivedCertficiateIsCA {
		publicKey = k.(*ssh.Certificate).SignatureKey
	}
	//log.Printf(ssh.FingerprintSHA256(k))
	//log.Printf("%#v", cert)

	nr := nagios.NagiosResult{}
	if *verifyAgainstSignatureShaSum == ssh.FingerprintSHA256(publicKey) {
		nr.ExitCode = 0
		nr.Text = "Received certificate's signature from " + url + " matched the given sha256 fingerprint " + *verifyAgainstSignatureShaSum
		nagios.NagiosExit(nr)
	} else {
		nr.ExitCode = 1
		nr.Text = "Received certificate's signature from " + url + " did not match the given sha256 fingerprint " + *verifyAgainstSignatureShaSum
		nagios.NagiosExit(nr)
	}

}
