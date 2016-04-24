package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"os"

	saml2 "github.com/andrewstuart/gosaml2-1"
	"github.com/golang/glog"
	dsig "github.com/russellhaering/goxmldsig"
)

const idpCert = `
-----BEGIN CERTIFICATE-----
MIIDODCCAiCgAwIBAgIUQH54kyyeacU69J2iwz9bzeLmMaswDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSY29sbGVnZS5jY2N0Y2EuZWR1MB4XDTE1MDYwNDIyMTAz
MVoXDTM1MDYwNDIyMTAzMVowHTEbMBkGA1UEAwwSY29sbGVnZS5jY2N0Y2EuZWR1
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlJhN20ng2VN/cTrWtqUI
NaUsrHCkYXbm2y1PTN4b6fJI5hbvcv+LWCuLkLi3+iPGlBpcHHfrdJcyhmBHRHQ9
Sos3RIH5Lsn1IgjWe3hxQQmVeEi5xVxnw2YZGHaeX4YnI1TEBJwhtJmyitk74LHy
bPGEqOJdApUnLz54L7I+252G/cOfEqUHMbxxtmHSc/9chF8bBxQ8OzIbJsByHnqi
awQHwtsttre7n328gVqmf1VHE27cfAYiSjuK5pCsx/1kuJMBN+kg/3Gg9oi6aR50
WX1VUF3IBcnTDeiAXRz3PgsT8FlVZou6Ik9NT/Y5IHOZVGk64SRDaG8FuGxLexXr
swIDAQABo3AwbjAdBgNVHQ4EFgQUjQwaAoY3u/iToIE3ADeNEW+Uu34wTQYDVR0R
BEYwRIISY29sbGVnZS5jY2N0Y2EuZWR1hi5odHRwczovL2NvbGxlZ2UuY2NjdGNh
LmVkdTo4NDQzL2lkcC9zaGliYm9sZXRoMA0GCSqGSIb3DQEBCwUAA4IBAQB26rdx
phN1YKad3yDhLg6Y1ZwbmAjc+l4QB1KSL+cLqhDn5iMy4VdWh8HpSKRqCwofLtlw
3qOwospj+mJaguXRMpjYODRQaKRkTrCGxJhuNrQxDXL/b6FOEIJnUYenbPevuNgR
Jc1VnREhWUUXT44KN5YUz9FEiG0BsBK8ecCPKBzTQ/hwaczhpqw6uqVMqxJaTGcn
lCUHJAhVHiA8lWJ7vaNPsJ86xBFs/F76EwyFXIKQaruvcvChU7GNNSYdNJBa6HO9
9QWdGbr5aNQ4diunnBQdrdjgbQIwyhKTfbFWa2l5vbqEKDc0dwuPa6c25l8ruqxq
CQ1CF8ZDDJ0XV6Ab
-----END CERTIFICATE-----
`

// MIIDODCCAiCgAwIBAgIUDPz+OwougAXSuQmKDyAEL46KlPgwDQYJKoZIhvcNAQEL
// BQAwHTEbMBkGA1UEAwwSY29sbGVnZS5jY2N0Y2EuZWR1MB4XDTE1MDYwNDIyMTA0
// NFoXDTM1MDYwNDIyMTA0NFowHTEbMBkGA1UEAwwSY29sbGVnZS5jY2N0Y2EuZWR1
// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApa0K3OtkHwOnBKSJ7PxT
// 7zry+p8kpu20d+whJs9mHW8w+DikLQ2orLPDZA34Xor0QdR6Y6+gqezIJqqpvuaj
// YTneQQtXD3neCGD9pPemyF4efEnl21YHryt6Juy6VXIcB6ytHGhmaWg41btdxweD
// li0b6M7Z6KAW5FjJUoqA+GqFY8rvdm0HZQN+ko4KRK7zTft6ZaPOSbQd7vMtU8bj
// Msh2XGLWx9G10jvCOFDUbsCNQ3xeFkV30rlUgjb6p2eRUSDWcVPs2Q/FG3t8TVfJ
// dDtRYps7QW0GDaCPM5hYnlSm+gXwkS8V0j8bGPjv7TfxxK3VMx6okIVsKga7swuZ
// 4QIDAQABo3AwbjAdBgNVHQ4EFgQUT56D4cLSoNxs17FBY+evwXvL2jowTQYDVR0R
// BEYwRIISY29sbGVnZS5jY2N0Y2EuZWR1hi5odHRwczovL2NvbGxlZ2UuY2NjdGNh
// LmVkdTo4NDQzL2lkcC9zaGliYm9sZXRoMA0GCSqGSIb3DQEBCwUAA4IBAQBiG0Nw
// KxslU74tcgjK8CBVahTs5s9Nh2s/En9lP6iWqS2wOHotZ19qqp+AJoIG0pJJpQ6o
// fRSHdWD2uHmF0F7Uzu1XBxxbV3oG8DmbhzUw2TAOsn0Czt8V30Tfn9U+auNW2XSb
// z27FACHplll7/T+pycCW6vUcw+boDJIG92TxqIMzlBQOzDGGOTGf/OaKXLb48rWT
// kEfMv//2Kh735TytX0bJsPmmCLlI9kLcrBNKgHGPNB7oeQNGnYOu+ALxSIugZ7MW
// LRx2jHND7RSVTetgfEEkkSzsebCxNKMdhIL62Z8VZgYUGD07EeV/3RZ0eV0q5Yf8
// BhBA6Owk2P264O4R

func main() {
	flag.Parse()

	idpURL := os.Getenv("IDP_SSO_URL")
	if idpURL == "" {
		idpURL = "https://idp.astuart.co/idp/profile/SAML2/Redirect/SSO"
	}

	spDir := os.Getenv("SP_DIR")
	glog.Infof(spDir)

	crt, err := tls.LoadX509KeyPair(spDir+"/tls.crt", spDir+"/tls.key")
	if err != nil {
		glog.Fatal(err)
	}

	block, _ := pem.Decode([]byte(idpCert))
	idpCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	certStore := &dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	}

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      idpURL,
		IdentityProviderIssuer:      "https://saml2.test.astuart.co/sso/saml2",
		AssertionConsumerServiceURL: "https://saml2.test.astuart.co/sso/saml2",
		AudienceURI:                 "https://saml2.test.astuart.co/sso/saml2",
		IDPCertificateStore:         certStore,
		SPKeyStore:                  saml2.TLSCertKeyStore(crt),
		SignAuthnRequests:           false,
	}
	//https://idp.astuart.co/idp/profile/SAML2/Unsolicited/SSO?providerId=http://portal.astuart.co/uPortal&target=/Login%3FcccMisCode=ZZ1

	http.HandleFunc("/sso/saml2", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()

		if err != nil {
			glog.Error("error parsing form", err)
			w.WriteHeader(500)
			return
		}

		info, err := sp.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))

		if err != nil {
			glog.Error("error retrieving assertion:", err)
			w.WriteHeader(500)
		}
		fmt.Fprintf(w, "%#v\n", info)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authURL, err := sp.BuildAuthURL("")
		if err != nil {
			glog.Error("Error building Auth URL", err)
			return
		}

		glog.V(3).Infof("auth URL: %s\n", authURL)
		w.Header().Set("Location", authURL)
		w.WriteHeader(302)
	})

	http.ListenAndServe(":8080", nil)
}
