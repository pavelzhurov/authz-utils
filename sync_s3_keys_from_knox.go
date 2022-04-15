package authz_utils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/golang/glog"
	"github.com/pinterest/knox"
)

// keyFolder is the directory where keys are cached
const keyFolder = "/var/lib/knox/v0/keys/"

type S3Keys struct {
	Name      string
	AccessKey string
	SecretKey string
}

type KnoxClient struct {
	knox.APIClient
}

type ClientOption func(*http.Client)

func NewKnoxClient(hostname string, tlsSkipVerify bool, timeout time.Duration, tlsConfig *tls.Config) *KnoxClient {

	// Knox client doesn't support retryable client, so retry number doesn't matter
	c, _ := newHttpClient(timeout, 0, tlsSkipVerify, tlsConfig)

	namespace, sa := getAuthPathAttributes()

	authHandler := func() string {
		if sa != "" && namespace != "" {
			return "0sspiffe://example.org/ns/" + namespace + "/sa/" + sa
		}
		return ""
	}

	if hostname == "" {
		hostname = "knox.knox:9000"
	}

	k := knox.NewClient(hostname, c.HTTPClient, authHandler, keyFolder, "")

	return &KnoxClient{
		k,
	}
}

func NewKnoxClientFromEnv() (*KnoxClient, error) {
	_, ok := os.LookupEnv("SPIFFE_CLIENT")
	if !ok {
		return nil, errors.New("SPIFFE certs are not provided")
	}

	// hostname is the host running the knox server
	hostname, ok := os.LookupEnv("KNOX_SERVER")
	if !ok {
		hostname = "knox.knox:9000"
	}

	caCert, ok := os.LookupEnv("KNOX_SERVER_CA")
	if !ok {
		return nil, errors.New("knox CA cert is not provided")
	}

	var (
		tlsSkipVerify bool
		timeout       time.Duration
		err           error
	)

	tlsSkipVerifyStr, ok := os.LookupEnv("KNOX_TLS_SKIP_VERIFY")
	if ok {
		tlsSkipVerify, err = strconv.ParseBool(tlsSkipVerifyStr)
		if err != nil {
			return nil, fmt.Errorf(ErrMissedConfigValue, "parse KNOX_INSECURE error")
		}
	}

	timeoutStr, ok := os.LookupEnv("KNOX_TIMEOUT")
	if ok {
		t, err := strconv.Atoi(timeoutStr)
		if err != nil {
			return nil, fmt.Errorf(ErrMissedConfigValue, "parse KNOX_TIMEOUT error")
		}

		timeout = time.Duration(t) * time.Millisecond
	}

	tlsConfig, err := knoxTlsConfig(hostname, caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to init knox client: %w", err)
	}

	return NewKnoxClient(hostname, tlsSkipVerify, timeout, tlsConfig), nil
}

func knoxTlsConfig(hostname, caCert string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		ServerName: hostname,
	}
	caCertString, ok := os.LookupEnv("KNOX_SERVER_CA")
	if !ok {
		return nil, fmt.Errorf("knox CA cert is not provided")
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(caCertString))
	certs, err := loadCertificates("/certs/*.key", "/certs/*.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to load spiffe certs: %w", err)
	}

	tlsConfig.Certificates = certs
	tlsConfig.RootCAs = caCertPool

	return tlsConfig, nil
}

func (k *KnoxClient) SyncKeysFromKnox() ([]S3Keys, error) {
	keys, err := k.GetKeys(map[string]string{})
	if err != nil {
		return nil, fmt.Errorf("can't get keys list. error: %v", err)
	}

	s3keys := make([]S3Keys, len(keys))
	for i, key := range keys {
		var s3key S3Keys

		if s3keyRaw, err := k.GetKey(key); err == nil && s3keyRaw != nil {
			s3keyRawData := s3keyRaw.VersionList.GetPrimary().Data

			err = json.Unmarshal(s3keyRawData, &s3key)
			if err != nil {
				return nil, fmt.Errorf("can't parse s3key data %+v", s3keyRawData)
			}

			s3keys[i] = S3Keys{
				Name:      key,
				AccessKey: s3key.AccessKey,
				SecretKey: s3key.SecretKey,
			}
		} else {
			return nil, fmt.Errorf("failed to get key from knox: %w", err)
		}

	}

	return s3keys, nil
}

func loadCertificates(paths ...string) ([]tls.Certificate, error) {
	certs := []tls.Certificate{}
	keys := []tls.Certificate{}

	for _, p := range paths {
		d, f := filepath.Split(p)

		g := glob.MustCompile(f, '/')

		err := filepath.Walk(d, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if !g.Match(info.Name()) {
				return nil
			}

			cert, err := addBlocks(path)
			if err != nil {
				return err
			}

			if len(cert.Certificate) > 0 {
				certs = append(certs, cert)
			}

			if cert.PrivateKey != nil {
				keys = append(keys, cert)
			}

			return nil
		})

		if err != nil {
			return certs, err
		}
	}

	for i := range certs {
		// We don't need to parse the public key for TLS, but we so do anyway
		// to check that it looks sane and matches the private key.
		x509Cert, err := x509.ParseCertificate(certs[i].Certificate[0])
		if err != nil {
			return certs, nil
		}

		switch pub := x509Cert.PublicKey.(type) {
		case *rsa.PublicKey:
			for _, key := range keys {
				priv, ok := key.PrivateKey.(*rsa.PrivateKey)
				if !ok {
					continue
				}
				if pub.N.Cmp(priv.N) != 0 {
					continue
				}

				certs[i].PrivateKey = priv
				break
			}
		case *ecdsa.PublicKey:
			for _, key := range keys {
				priv, ok := key.PrivateKey.(*ecdsa.PrivateKey)
				if !ok {
					continue
				}
				if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
					continue
				}

				certs[i].PrivateKey = priv
				break
			}
		case ed25519.PublicKey:
			for _, key := range keys {
				priv, ok := key.PrivateKey.(ed25519.PrivateKey)
				if !ok {
					continue
				}
				if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
					continue
				}

				certs[i].PrivateKey = priv
				break
			}
		default:
			return certs, fmt.Errorf("tls: unknown public key algorithm")
		}
	}

	return certs, nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("tls: failed to parse private key")
}

func addBlocks(path string) (tls.Certificate, error) {
	cert := tls.Certificate{}

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return cert, err
	}

	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		raw = rest

		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
			continue
		}

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			key, err := parsePrivateKey(block.Bytes)
			if err != nil {
				return cert, fmt.Errorf("failure reading private key from \"%s\": %s", path, err)
			}
			cert.PrivateKey = key
			continue
		}
	}

	return cert, nil
}

func getAuthPathAttributes() (string, string) {
	_, ok := os.LookupEnv("SPIFFE_CLIENT")
	if ok {
		namespace, ok := os.LookupEnv("NAMESPACE")
		if !ok {
			glog.Error("NAMESPACE is not defined")
		}
		serviceaccount, ok := os.LookupEnv("POD_SA")
		if !ok {
			glog.Error("POD_SA is not defined")
		}

		return namespace, serviceaccount
	}
	return "", ""
}
