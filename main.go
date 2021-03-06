package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	_ "net/http/pprof"

	"github.com/golang/glog"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/prometheus/client_golang/prometheus"
	saml2 "github.com/russellhaering/gosaml2"
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

var (
	store = sessions.NewCookieStore([]byte("secret passphrase"))

	redirects = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "redirects",
		Help: "Number of redirects sent",
	})

	saml2Logins = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "saml_logins",
		Help: "Number of logins processed via saml2",
	})
)

func init() {
	prometheus.MustRegister(redirects)
	prometheus.MustRegister(saml2Logins)

	go func() {
		log.Println(http.ListenAndServe(":6060", nil))
	}()

}

const authKey = "authn"

func main() {
	glog.Info("Starting")

	flag.Parse()

	tmpl, err := template.New("frontPage").Parse(fp)
	if err != nil {
		glog.Fatal("Template error", err)
	}

	gob.Register(&saml2.AssertionInfo{})

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

	glog.Info("Loaded keys")

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
		SPKeyStore:                  dsig.TLSCertKeyStore(crt),
		SignAuthnRequests:           true,
		SignAuthnRequestsAlgorithm:  dsig.CanonicalXML10AlgorithmId,
	}
	//https://idp.astuart.co/idp/profile/SAML2/Unsolicited/SSO?providerId=http://portal.astuart.co/uPortal&target=/Login%3FcccMisCode=ZZ1

	mux := http.NewServeMux()

	mux.HandleFunc("/sso/saml2", func(w http.ResponseWriter, r *http.Request) {
		sess, err := store.Get(r, "saml")
		if err != nil {
			glog.Error("store error")
		}
		err = r.ParseForm()

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

		sess.Values[authKey] = *info
		sess.Values["visits"] = 0
		err = sess.Save(r, w)
		if err != nil {
			glog.Error("Error saving session", err)
		}

		url := r.FormValue("RelayState")
		glog.Info("URL: ", url)

		if url == "" {
			url = "/"
		}

		saml2Logins.Inc()

		http.Redirect(w, r, url, 302)
	})

	mux.HandleFunc("/.status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Success")
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		s, err := store.Get(r, "saml")
		if err != nil {
			glog.Error("Error getting session", err)
			http.Error(w, "Error", 500)
		}

		s.Values[authKey] = nil
		if err := s.Save(r, w); err != nil {
			glog.Error("Error clearing session", err)
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		sess, err := store.Get(r, "saml")
		if err != nil {
			glog.Error("Error getting session", err)
			w.WriteHeader(500)
			return
		}

		authn, ok := sess.Values[authKey]

		//If no session
		if !ok || authn == nil {
			if err != nil {
				glog.V(3).Info(err)
			}

			authURL, err := sp.BuildAuthURL("/")
			if err != nil {
				glog.Error("Error building Auth URL", err)
				return
			}

			glog.V(3).Infof("auth URL: %s\n", authURL)
			http.Redirect(w, r, authURL, 302)
			return
		}

		if r.URL.Path == "/" {
			sess.Values["visits"] = sess.Values["visits"].(int) + 1
			sess.Save(r, w)
		}

		info, ok := authn.(*saml2.AssertionInfo)
		if !ok {
			glog.Error("No assertion")
			return
		}

		m := make(map[string]interface{})

		m["name"] = info.Values.Get("urn:oid:2.5.4.42")
		m["userInfo"] = info
		m["visits"] = sess.Values["visits"]

		bs, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			glog.Error(err)
		}

		m["json"] = string(bs)

		err = tmpl.Execute(w, m)
		if err != nil {
			glog.Error(err)
		}
	})

	glog.Info("Listening")

	mux.Handle("/metrics", prometheus.Handler())

	glog.Fatal(http.ListenAndServe(":8080", prometheus.InstrumentHandler("mux", context.ClearHandler(mux))))
}

const fp = `
<html>
	<head>
		<title>
			Hello {{ .name }}
		</title>
	</head>
	<body>
		<h1>Hello there, {{ .name }} <a href="/logout">Logout</a></h1>
		<div>So glad to see you! You've been here {{ .visits }} times.</div>
		{{ range $i, $e := .userInfo.Values }}
		<div>
		{{ $e.FriendlyName }} ({{ $e.Name }}):
		<ul>
		{{ range $in, $v := $e.Values }}<li>{{ $v }}</li>
		{{- end }}
		</ul>
		</div>
		{{ end }}
	</body>
</html>
`
