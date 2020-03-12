#### usage
```
Usage of ./check_openssh_cert:
  -debug
    	log debug output, defaults to false
  -sslSkipVerify
    	add InsecureSkipVerify: true to the http client for invalid certificates
  -url string
    	which URL to send the GET to to get the certificate (default "https://127.0.0.1:443/check")
  -verifyAgainstSignatureShaSum string
    	file location to check the recieved certificat's signature against
  -version
    	show build time and version number
```

#### build
```
$ go get
$ BUILDTIME=$(date -u '+%Y-%m-%d_%H:%M:%S') && go build -ldflags "-X main.buildtime=$BUILDTIME"
```

##### example

```
./check_openssh_cert -url https://127.0.0.1:443/check -verifyAgainstSignatureShaSum SHA256:Ar7bYZIf/BvWbwkFEukZgjK8lRpzvsvbjGbZ9SwWshE -debug
2020/03/12 18:35:18 Debug doRequest(): sending request to https://127.0.0.1:443/check
2020/03/12 18:35:18 Debug doRequest(): Received response: {
  "ca": "ekca1",
  "cert": "ssh-rsa-cert-v01@openssh.com AAAAH...."
}
2020/03/12 18:35:18 Received valid response from https://127.0.0.1:443/check
OK: Received certificate's signature from https://127.0.0.1:443/check matched the given sha256 fingerprint SHA256:Ar7bYZIf/BvWbwkFEukZgjK8lRpzvsvbjGbZ9SwWshE|
```
