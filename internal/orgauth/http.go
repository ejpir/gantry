package orgauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"
)

// All discovery, token, and JWKS requests use this client. Redirects are
// forbidden so neither authorization codes nor tokens can follow a redirect.
func oidcClient(ca []byte) (*http.Client, func(), error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if len(ca) != 0 && !roots.AppendCertsFromPEM(ca) {
		return nil, nil, fmt.Errorf("OIDC CA file contains no certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	transport.MaxResponseHeaderBytes = 64 << 10
	return &http.Client{
		Transport: boundedTransport{base: transport},
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("OIDC HTTP redirects are not allowed")
		},
	}, transport.CloseIdleConnections, nil
}

type boundedTransport struct{ base http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, err := httpsURL(r.URL.String()); err != nil {
		return nil, err
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	const maxResponse = 1 << 20
	if response.ContentLength > maxResponse {
		_ = response.Body.Close()
		return nil, fmt.Errorf("OIDC response too large")
	}
	response.Body = &boundedBody{ReadCloser: response.Body, left: maxResponse + 1}
	return response, nil
}

type boundedBody struct {
	io.ReadCloser
	left int
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if len(p) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= n
	if b.left <= 0 {
		return n, fmt.Errorf("OIDC response too large")
	}
	return n, err
}
