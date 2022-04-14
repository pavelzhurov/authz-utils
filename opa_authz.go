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
	"github.com/hashicorp/go-retryablehttp"
)

const (
	ErrMissedConfigValue = "failed to init authenticator from env: %s"

	HeaderContentType = "Content-Type"

	ContentTypeApplicationJSON = "application/json"

	AuthzOPADefaultRetries = 5
)

type Authorizer struct {
	region     string
	accountID  string
	projectID  string
	resourceID string
	opaURL     string

	client *retryablehttp.Client
}

func NewAuthorizer(region, accountID, projectID, resourceID, opaURL string, clientTimeout time.Duration, retries int, tlsSkipVerify bool) *Authorizer {
	retryableClient, _ := newHttpClient(clientTimeout, AuthzOPADefaultRetries, tlsSkipVerify, nil)
	return &Authorizer{
		region:     region,
		accountID:  accountID,
		projectID:  projectID,
		resourceID: resourceID,
		opaURL:     opaURL,
		client:     retryableClient,
	}
}

func NewAuthenticatorFromEnv() (*Authorizer, error) {
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

	var retries int
	retriesStr, ok := os.LookupEnv("AUTHZ_OPA_RETRIES")
	if ok {
		retries, err = strconv.Atoi(retriesStr)
		if err != nil {
			return nil, fmt.Errorf(ErrMissedConfigValue, "parse KNOX_INSECURE error")
		}
	} else {
		retries = AuthzOPADefaultRetries
	}

	retryableClient, err := newHttpClient(time.Duration(timeout)*time.Millisecond, retries, insecure, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrMissedConfigValue, err)
	}

	return &Authorizer{
		region:     region,
		accountID:  accountID,
		projectID:  projectID,
		resourceID: resourceID,
		opaURL:     opaURL,
		client:     retryableClient,
	}, nil
}

func (a *Authorizer) Authz(partition, service, username, action, path string, tags map[string]string) (bool, error) {
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

	retriableRequest, _ := retryablehttp.FromRequest(req)
	res, err := a.client.Do(retriableRequest)
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

func newHttpClient(clientTimeout time.Duration, retries int, tlsSkipVerify bool, tlsConfig *tls.Config) (*retryablehttp.Client, error) {
	if retries < 0 {
		return nil, fmt.Errorf("Negative retries number: %d", retries)
	}

	c := retryablehttp.NewClient()
	c.RetryMax = retries
	if clientTimeout != 0 {
		c.HTTPClient.Timeout = clientTimeout
	}

	if tlsConfig != nil {
		c.HTTPClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		return c, nil
	}
	c.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tlsSkipVerify,
		},
	}

	return c, nil
}
