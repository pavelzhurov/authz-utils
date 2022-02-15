package authz_utils

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/golang/glog"
)

func Authz(partition, service, username, action, path string, tags map[string]string) bool {
	glog.V(3).Infof("Action: %v, path: %v, tags: %+v", action, path, tags)

	region, ok := os.LookupEnv("REGION")
	if !ok {
		glog.V(1).Info("REGION is not provided")
		return false
	}

	account_id, ok := os.LookupEnv("ACCOUNT_ID")
	if !ok {
		glog.V(1).Info("ACCOUNT_ID is not provided")
		return false
	}

	project_id, ok := os.LookupEnv("PROJECT_ID")
	if !ok {
		glog.V(1).Info("PROJECT_ID is not provided")
		return false
	}

	resource_id, ok := os.LookupEnv("RESOURCE_ID")
	if !ok {
		glog.V(1).Info("RESOURCE_ID is not provided")
		return false
	}

	url, ok := os.LookupEnv("OPA_URL")
	if !ok {
		glog.V(1).Info("OPA URL is not provided")
		return false
	}

	opa_input, _ := json.Marshal(map[string]interface{}{
		"partition":   partition,
		"service":     service,
		"region":      region,
		"account_id":  account_id,
		"project_id":  project_id,
		"resource_id": resource_id,
		"path":        path,
		"action":      action,
		"tags":        tags,
		"user":        username,
	})

	response, err := http.Post(url, "application/json", bytes.NewBuffer(opa_input))
	//Handle Error
	if err != nil {
		glog.V(3).Infof("An Error Occured %v", err)
		return false
	}
	responseBody, _ := ioutil.ReadAll(response.Body)
	var resp bool
	err_body := json.Unmarshal(responseBody, &resp)
	if err_body != nil {
		glog.V(3).Infof("An Error Occured during authorization %v", err_body)
		return false
	}

	glog.V(3).Infof("%+v\n", resp)

	return resp
}
