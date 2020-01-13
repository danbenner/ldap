package ldap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

/*
	LDAP ...
		- init():
			- initialize with simple PING test to LDAP server
		- LDAP():
			- initialize env vars
			- create request body for POST to LDAP server
			- make request, then unmarshal into []Response, then return
		- parseResponseOfMemberOfRoles()
		- doesArrayXContainAnyStringsInArrayY()
		- makeAPIRequest()
		- CustomLDAPSearch():
			- search, parse roles, find matches
		- pingLDAPAPI()
			- for testing and initialization

		* NOTE: The CustomLDAPSearch relies on 'acceptedUserGroups' being correctly populated
*/

type searchFilter struct {
	Filter     string   `json:"filter"`
	Attributes []string `json:"attributes"`
	SizeLimit  int      `json:"sizeLimit"`
	DN         string   `json:"dn"`
}

// Response ...
type Response struct {
	DN       string   `json:"dn"`
	Controls []string `json:"controls"`
	CN       string   `json:"cn"`
	MemberOf []string `json:"memberOf"`
}

type message struct {
	Responses []Response `json:"message"`
}

func init() {
	status, err := pingLDAPAPI()
	if err != nil {
		log.Printf("STATUS: %v, ERROR: %v\n", status, err.Error())
	} else {
		log.Printf("LDAP Successfully initialized ...\n")
	}
}

// LDAP ...
func LDAP(subjectID string) ([]Response, int, error) {

	// --------------------------------- INIT -------------------------------- //
	url := os.Getenv("LDAP_API_URL")
	auth := os.Getenv("LDAP_API_BASIC_AUTH")
	switch {
	case url == "":
		return nil, 0, errors.New("ERROR: LDAP failed to get LDAP_API_URL")
	case url == "":
		return nil, 0, errors.New("ERROR: LDAP failed to get LDAP_API_BASIC_AUTH")
	}

	// ------------------------- CREATE REQUEST BODY ------------------------- //
	// 	NOTE: these fields were determined here:
	//		https://github.com/go-ldap/ldap/blob/master/examples_test.go
	requestBody, err := json.Marshal(searchFilter{
		Filter:     fmt.Sprintf("(&(objectClass=person)(objectClass=user)(userAccountControl=512)(sAMAccountName=%s)(!(objectClass=computer)))", subjectID),
		Attributes: []string{"dn", "cn", "sAMAccountName", "mail", "memberOf"},
		SizeLimit:  0,
		DN:         "DC=a,DC=com",
	})
	if err != nil {
		log.Printf("ERROR: Failed to Marshal searchFilter: %v\n", err.Error())
		return nil, 0, err
	}

	// ------------------------ REQUEST AND UNMARSHAL ------------------------ //
	bodyEncoded, statusCode, err := makeAPIRequest("POST", url, requestBody, auth)
	if err != nil {
		return nil, statusCode, err
	}
	var messageDecoded message
	err2 := json.Unmarshal(bodyEncoded, &messageDecoded)
	if err2 != nil {
		log.Printf("ERROR: failed to unmarshal: %v\n", string(bodyEncoded))
		return nil, statusCode, err2
	}

	return messageDecoded.Responses, statusCode, nil
}

// parseResponseOfMemberOfRoles ...
func parseResponseOfMemberOfRoles(arr []Response) ([]string, error) {
	// NOTE: the number of Responses will typically be 1
	if len(arr) != 1 {
		return nil, errors.New("ERROR: Length of arrayOfResponses != 1")
	}
	for i, role := range arr[0].MemberOf {
		commaSpliceResult := strings.Split(role, ",")
		equalsSliceResult := strings.Split(commaSpliceResult[0], "=")
		arr[0].MemberOf[i] = equalsSliceResult[1]
	}
	return arr[0].MemberOf, nil
}

// doesArrayXContainAnyStringsInArrayY ...
func doesArrayXContainAnyStringsInArrayY(x []string, y []string) []string {
	matches := []string{}
	for _, group := range x {
		for _, subGroup := range y {
			if group == subGroup {
				matches = append(matches, subGroup)
			}
		}
	}
	return matches
}

// makeAPIRequest ... NOTE: need status code returned!
func makeAPIRequest(method string, url string, requestBody []byte, auth string) ([]byte, int, error) {
	var req *http.Request
	if requestBody != nil {
		req, _ = http.NewRequest(method, url, bytes.NewBuffer(requestBody))
	} else {
		req, _ = http.NewRequest(method, url, nil)
	}
	if auth != "" {
		req.Header.Add(`Authorization`, `Basic `+auth)
	}
	req.Header.Add(`Content-Type`, `application/json`)
	client := NewClient()
	response, err := client.Do(req)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	defer response.Body.Close()
	bodyEncoded, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return bodyEncoded, response.StatusCode, nil
}

// CustomLDAPSearch ...
func CustomLDAPSearch(subjectID string) ([]string, int, error) {

	var (
		acceptedUserGroups = []string{
			"some_user_group",
		}
	)

	// SEARCH
	response, statusCode, err := LDAP(subjectID)
	if err != nil {
		return nil, statusCode, err
	}
	// PARSE ROLES
	adGroups, err := parseResponseOfMemberOfRoles(response)
	if err != nil {
		return nil, 0, err
	}
	// FIND MATCHES
	matches := doesArrayXContainAnyStringsInArrayY(adGroups, acceptedUserGroups)
	if len(matches) == 0 {
		return matches, 0, errors.New("No matching AD Groups")
	}

	return matches, 0, nil
}

// pingLDAPAPI ...
func pingLDAPAPI() (int, error) {
	_, status, err := LDAP("")
	if err != nil {
		return status, errors.New("Failed to Ping LDAP")
	}
	return status, nil
}
