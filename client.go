package tlstest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

type KeyGenerator interface {
	GenerateKey(r io.Reader) (interface{}, error)
}

type AlgoECDSA struct {
	Curve elliptic.Curve
}

func ECDSA256() *AlgoECDSA {
	return &AlgoECDSA{
		Curve: elliptic.P256(),
	}
}

func (e *AlgoECDSA) GenerateKey(r io.Reader) (interface{}, error) {
	c := e.Curve
	if c == nil {
		c = elliptic.P256()
	}
	return ecdsa.GenerateKey(c, r)
}

var _ KeyGenerator = &AlgoECDSA{}

type AlgoRSA struct {
	Bits int
}

func RSA2048() *AlgoRSA {
	return &AlgoRSA{
		Bits: 2048,
	}
}

func (e *AlgoRSA) GenerateKey(r io.Reader) (interface{}, error) {
	b := e.Bits
	if b == 0 {
		b = 2048
	}
	return rsa.GenerateKey(r, b)
}

var _ KeyGenerator = &AlgoRSA{}

type Options struct {
	Hosts        []string
	Organization string
	NotBefore    time.Time
	NotAfter     time.Time

	Rand io.Reader
}

func publicKey(priv interface{}) (interface{}, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey), nil
	default:
		return nil, fmt.Errorf("%T: unsupported private key", k)
	}
}

// NewCertificate returns PEM encoded certificate
func NewCertificate(g KeyGenerator, o Options) (keyPEMBlock, certPEMBlock []byte, err error) {
	r := o.Rand
	if r == nil {
		r = rand.Reader
	}

	privKey, err := g.GenerateKey(r)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := publicKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	keyUsage := x509.KeyUsageDigitalSignature
	if _, ok := privKey.(*rsa.PrivateKey); ok {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	notBefore := o.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now()
	}
	notAfter := o.NotAfter
	if notAfter.IsZero() {
		notAfter = notBefore.Add(10 * time.Minute)
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(r, limit)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{o.Organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range o.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	certBytes, err := x509.CreateCertificate(r, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}
	certPEMBlock = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEMBlock = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	return
}
