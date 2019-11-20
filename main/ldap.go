package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	ldap "github.com/go-ldap/ldap"
)

var (
	serviceAccountID   = ""
	serviceAccountPASS = ""
	ldapServerName     = ""
	baseDomainName     = "MUST CHANGE"
)

func init() {
	serviceAccountID := os.Getenv("SERVICE_ACCOUNT_ID")
	serviceAccountPASS := os.Getenv("SERVICE_ACCOUNT_PASS")
	ldapServerName := os.Getenv("LDAP_SERVER_NAME")
	baseDomainName := "MUST CHANGE"
	switch {
	case serviceAccountID == "":
		fmt.Printf("ERROR: Failed to initialize LDAP; serviceAccountID invalid\n")
	case serviceAccountPASS == "":
		fmt.Printf("ERROR: Failed to initialize LDAP; serviceAccountPASS invalid\n")
	case ldapServerName == "":
		fmt.Printf("ERROR: Failed to initialize LDAP; ldapServerName invalid\n")
	}
	err := pingLDAPServer(ldapServerName, serviceAccountID, serviceAccountPASS, baseDomainName)
	if err != nil {
		fmt.Printf("%v\n", err.Error())
	} else {
		fmt.Printf("LDAP Successfully initialized ...\n")
	}
}

// Response ...
type Response struct {
	CN             string   `json:"cn"`
	SAMAccountName string   `json:"sAMAccountName"`
	Mail           string   `json:"mail"`
	MemberOf       []string `json:"memberOf"`
}

// ExampleLDAPSearch ...
func ExampleLDAPSearch(subjectID string) ([]string, error) {

	var (
		acceptedUserGroups = []string{
			"groupA",
			"groupB",
		}
	)

	// SEARCH
	response, err := LDAP(ldapServerName, serviceAccountID, serviceAccountPASS, baseDomainName, subjectID)
	if err != nil {
		return nil, err
	}
	// PARSE ROLES
	adGroups, err := parseMemberOfRoles(response)
	if err != nil {
		return nil, err
	}
	// ALLOWED MATCHES
	matches := doesArrayXContainAnyStringsInArrayY(adGroups, acceptedUserGroups)

	return matches, nil
}

// LDAP (Lightweight Directory Access Protocol) ..
// - requires: service account ID and Password and subject ID
func LDAP(serverName string, serviceAccountID string, serviceAccountPASS string, baseDomainName string, subjectID string) ([]Response, error) {

	// CREATE CONNECTION
	ldapConnection, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", serverName, 389))
	if err != nil {
		return nil, err
	}
	defer ldapConnection.Close()

	// BIND (AUTHORIZED) SERVICE ACCOUNT
	err = ldapConnection.Bind(serviceAccountID+"@"+baseDomainName+".com", serviceAccountPASS)
	if err != nil {
		return nil, err
	}

	/*
		scope ENUMERATED {
			baseObject              (0),
			singleLevel             (1),
			wholeSubtree            (2),
		},
		derefAliases ENUMERATED {
			neverDerefAliases       (0),
			derefInSearching        (1),
			derefFindingBaseObj     (2),
			derefAlways             (3),
		},
		DN == Distinguished Name
		CN == Relative Distinguished Name (RDN)
		SAMAccountName == Unique Domain Name (logon name)
		Mail == Email Address
		MemberOf == Active Directory Groups
	*/

	// CREATE SEARCH REQUEST
	result, err := ldapConnection.Search(&ldap.SearchRequest{
		BaseDN:       "dc=" + baseDomainName + ",dc=com",
		Scope:        2, // wholeSubtree
		DerefAliases: 0, // neverDerefAliases
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", subjectID),
		Attributes:   []string{"dn", "cn", "sAMAccountName", "mail", "memberOf"},
		Controls:     nil,
	})

	if err != nil {
		return nil, err
	}

	response := []Response{}

	// PARSE ENTRIES
	// NOTE: the number of entries will typically be 1
	for _, entry := range result.Entries {
		response = append(response, Response{
			entry.GetAttributeValue("cn"),
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("mail"),
			entry.GetAttributeValues("memberOf"),
		})
	}

	return response, nil
}

// parseMemberOfRoles ...
func parseMemberOfRoles(arr []Response) ([]string, error) {
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

// pingLDAPServer ...
func pingLDAPServer(serverName string, serviceAccountID string, serviceAccountPASS string, baseDomainName string) error {

	// CREATE CONNECTION
	ldapConnection, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", serverName, 389))
	if err != nil {
		return err
	}
	defer ldapConnection.Close()

	// BIND (AUTHORIZED) SERVICE ACCOUNT
	err = ldapConnection.Bind(serviceAccountID+"@"+baseDomainName+".com", serviceAccountPASS)
	if err != nil {
		return err
	}

	// CREATE SEARCH REQUEST
	_, err = ldapConnection.Search(&ldap.SearchRequest{
		BaseDN:       "dc=" + baseDomainName + ",dc=com",
		Scope:        2, // wholeSubtree
		DerefAliases: 0, // neverDerefAliases
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ""),
		Attributes:   []string{"dn", "cn", "sAMAccountName", "mail", "memberOf"},
		Controls:     nil,
	})
	if err != nil {
		return err
	}

	return nil
}
