package jwt

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
)

type CertificateThumbprintConfirmation struct {
	CertificateThumbprint []byte `json:"x5t#S256"` // https://www.rfc-editor.org/rfc/rfc8705#name-jwt-certificate-thumbprint-
}

type certificateThumbprintConfirmer struct {
	peer *x509.Certificate // If set, Peer is used for confirmation
}

func NewCertificateThumbprintConfirmerFromRequest(req *http.Request) (Confirmer[CertificateThumbprintConfirmation], error) {
	if req.TLS == nil {
		return nil, fmt.Errorf("http request was not performed with TLS")
	}
	return NewCertificateThumbprintConfirmerFromTLS(req.TLS)
}

func NewCertificateThumbprintConfirmerFromTLS(tls *tls.ConnectionState) (Confirmer[CertificateThumbprintConfirmation], error) {
	if len(tls.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificate")
	}
	return NewCertificateThumbprintConfirmer(tls.PeerCertificates[0]), nil
}

func NewCertificateThumbprintConfirmer(peer *x509.Certificate) Confirmer[CertificateThumbprintConfirmation] {
	return &certificateThumbprintConfirmer{peer}
}

// Confirm implements Confirmer
func (confirmer *certificateThumbprintConfirmer) Confirm(cnf *CertificateThumbprintConfirmation) error {
	x5t := sha256.Sum256(confirmer.peer.Raw)
	if !bytes.Equal(cnf.CertificateThumbprint, x5t[:]) {
		return fmt.Errorf("cnf: certificate thumbprints did not match")
	}
	return nil
}
