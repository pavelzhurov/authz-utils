package authz_utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang/glog"
)

const (
	ErrMissedConfigValue = "failed to init authenticator from env: %s"

	HeaderContentType = "Content-Type"

	ContentTypeApplicationJSON = "application/json"
)

type Authenticator struct {
	region     string
	accountID  string
	projectID  string
	resourceID string
	opaURL     string

	client *http.Client
}

func NewAuthenticator(region, accountID, projectID, resourceID, opaURL string, clientTimeout time.Duration, tlsSkipVerify bool) *Authenticator {
	return &Authenticator{
		region:     region,
		accountID:  accountID,
		projectID:  projectID,
		resourceID: resourceID,
		opaURL:     opaURL,
		client:     newHttpClient(clientTimeout, tlsSkipVerify, nil),
	}
}

func NewAuthenticatorFromEnv() (*Authenticator, error) {
	region, ok := os.LookupEnv("AUTHZ_REGION")
	if !ok {
		return nil, fmt.Errorf(ErrMissedConfigValue, "AUTHZ_REGION in not provided")
	}

	accountID, ok := os.LookupEnv("AUTHZ_ACCOUNT_ID")
	if !ok {
		return nil, fmt.Errorf(ErrMissedConfigValue, "AUTHZ_ACCOUNT_ID in not provided")
	}

	projectID, ok := os.LookupEnv("AUTHZ_PROJECT_ID")
	if !ok {
		return nil, fmt.Errorf(ErrMissedConfigValue, "AUTHZ_PROJECT_ID in not provided")
	}

	resourceID, ok := os.LookupEnv("AUTHZ_RESOURCE_ID")
	if !ok {
		return nil, fmt.Errorf(ErrMissedConfigValue, "AUTHZ_RESOURCE_ID in not provided")
	}

	opaURL, ok := os.LookupEnv("AUTHZ_OPA_URL")
	if !ok {
		return nil, fmt.Errorf(ErrMissedConfigValue, "AUTHZ_OPA_URL in not provided")
	}

	var (
		insecure bool
		timeout  time.Duration
		err      error
	)

	// Milliseconds
	timeoutStr, ok := os.LookupEnv("AUTHZ_OPA_TIMEOUT")
	if ok {
		t, err := strconv.Atoi(timeoutStr)
		if err != nil {
			return nil, fmt.Errorf(ErrMissedConfigValue, "parse KNOX_INSECURE error")
		}

		timeout = time.Duration(t) * time.Millisecond
	}

	insecureStr, ok := os.LookupEnv("AUTHZ_OPA_INSECURE")
	if ok {
		insecure, err = strconv.ParseBool(insecureStr)
		if err != nil {
			return nil, fmt.Errorf(ErrMissedConfigValue, "parse AUTHZ_OPA_INSECURE error")
		}
	}

	return &Authenticator{
		region:     region,
		accountID:  accountID,
		projectID:  projectID,
		resourceID: resourceID,
		opaURL:     opaURL,
		client:     newHttpClient(time.Duration(timeout)*time.Millisecond, insecure, nil),
	}, nil
}

func (a *Authenticator) Authz(partition, service, username, action, path string, tags map[string]string) (bool, error) {
	glog.V(3).Infof("Action: %v, path: %v, tags: %+v", action, path, tags)

	input, _ := json.Marshal(map[string]interface{}{
		"partition":   partition,
		"service":     service,
		"region":      a.region,
		"account_id":  a.accountID,
		"project_id":  a.projectID,
		"resource_id": a.resourceID,
		"path":        path,
		"action":      action,
		"tags":        tags,
		"user":        username,
	})

	req, err := http.NewRequest(http.MethodPost, a.opaURL, bytes.NewReader(input))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add(HeaderContentType, ContentTypeApplicationJSON)

	res, err := a.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("auth request failed: %w", err)
	}

	responseBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	var resp bool
	err = json.Unmarshal(responseBody, &resp)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	return resp, nil
}

func newHttpClient(clientTimeout time.Duration, tlsSkipVerify bool, tlsConfig *tls.Config) *http.Client {
	var c *http.Client
	if clientTimeout != 0 {
		c = &http.Client{
			Timeout: clientTimeout,
		}
	} else {
		c = http.DefaultClient
	}

	if tlsConfig != nil {
		tlsConfig.InsecureSkipVerify = tlsSkipVerify
		c.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		return c
	}
	c.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tlsSkipVerify,
		},
	}

	return c
}
