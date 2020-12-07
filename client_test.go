package tlstest_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/lufia/tlstest"
)

func ExampleNewCertificate_server() {
	keyPEMBlock, certPEMBlock, err := tlstest.NewCertificate(&tlstest.ECDSA256{}, tlstest.Options{
		Organization: "example&co",
		Hosts:        []string{"127.0.0.1"},
	})
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		log.Fatalln("X509KeyPair:", err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	s.StartTLS()
	defer s.Close()

	c := s.Client()
	resp, err := c.Get(s.URL)
	if err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()
	fmt.Println(resp.TLS.PeerCertificates[0].Subject)
	// Output: O=example&co
}

func ExampleNewCertificate_client() {
	_, certPEMBlock, err := tlstest.NewCertificate(&tlstest.ECDSA256{}, tlstest.Options{
		Organization: "example&co",
	})
	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}
	certPool.AppendCertsFromPEM(certPEMBlock)
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}
	_ = c
}
