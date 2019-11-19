package main

import (
	"os"
	"reflect"
	"testing"
)

func TestLDAP(t *testing.T) {
	var (
		serviceAccountID   = os.Getenv("SERVICE_ACCOUNT_ID")
		serviceAccountPASS = os.Getenv("SERVICE_ACCOUNT_PASS")
		ldapServerName     = os.Getenv("LDAP_SERVER_NAME")
		baseDomainName     = "MUST CHANGE"
		test4r             = []Response{}
		// r1                 = Response{
		// 	CN:             "Test",
		// 	SAMAccountName: "Test test",
		// 	Mail:           "Ohiouser4.S.Test@bchpohio.com",
		// 	MemberOf: []string{
		// 		"CN=a", "CN=b",
		// 	},
		// }
		// test5r = []Response{r1}
	)
	type args struct {
		serverName         string
		serviceAccountID   string
		serviceAccountPASS string
		baseDomainName     string
		subjectID          string
	}
	tests := []struct {
		name    string
		args    args
		want    []Response
		wantErr bool
	}{
		{"1", args{
			serverName: "", serviceAccountID: "", serviceAccountPASS: "", baseDomainName: "", subjectID: "",
		}, nil, true},
		{"2", args{
			serverName: ldapServerName, serviceAccountID: "", serviceAccountPASS: "", baseDomainName: "", subjectID: "",
		}, nil, true},
		{"3", args{
			serverName: ldapServerName, serviceAccountID: serviceAccountID, serviceAccountPASS: serviceAccountPASS, baseDomainName: "", subjectID: "",
		}, nil, true},
		{"4", args{
			serverName: ldapServerName, serviceAccountID: serviceAccountID, serviceAccountPASS: serviceAccountPASS, baseDomainName: baseDomainName, subjectID: "",
		}, test4r, false},
		// {"5", args{
		// 	serverName: ldapServerName, serviceAccountID: serviceAccountID, serviceAccountPASS: serviceAccountPASS, baseDomainName: baseDomainName, subjectID: "test",
		// }, test5r, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LDAP(
				tt.args.serverName,
				tt.args.serviceAccountID,
				tt.args.serviceAccountPASS,
				tt.args.baseDomainName,
				tt.args.subjectID,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("LDAP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LDAP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseMemberOfRoles(t *testing.T) {
	var (
		r1 = Response{
			CN:             "",
			SAMAccountName: "",
			Mail:           "",
			MemberOf:       []string{"cn=a", "cn=b"},
		}
		r2 = Response{
			CN:             "",
			SAMAccountName: "",
			Mail:           "",
			MemberOf:       []string{"cn=b", "cn=c"},
		}
		test1r = []Response{r1, r2}
		test2r = []Response{r1}
		test2w = []string{"a", "b"}
	)
	type args struct {
		arr []Response
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{"1", args{arr: test1r}, nil, true},
		{"2", args{arr: test2r}, test2w, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMemberOfRoles(tt.args.arr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMemberOfRoles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseMemberOfRoles() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_doesArrayXContainAnyStringsInArrayY(t *testing.T) {
	var (
		test1a = []string{""}
		test1b = []string{""}
		test2a = []string{"a"}
		test2b = []string{"a"}
		test3a = []string{"a"}
		test3b = []string{"b"}
		test4a = []string{"a", "b", "c", "d"}
		test4b = []string{"b", "d"}
	)
	type args struct {
		x []string
		y []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"1", args{x: test1a, y: test1b}, []string{""}},
		{"2", args{x: test2a, y: test2b}, []string{"a"}},
		{"3", args{x: test3a, y: test3b}, []string{}},
		{"4", args{x: test4a, y: test4b}, []string{"b", "d"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := doesArrayXContainAnyStringsInArrayY(tt.args.x, tt.args.y); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("doesArrayXContainAnyStringsInArrayY() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pingLDAPServer(t *testing.T) {
	var (
		serviceAccountID   = os.Getenv("SERVICE_ACCOUNT_ID")
		serviceAccountPASS = os.Getenv("SERVICE_ACCOUNT_PASS")
		ldapServerName     = os.Getenv("LDAP_SERVER_NAME")
		baseDomainName     = "MUST CHANGE"
	)
	type args struct {
		serverName         string
		serviceAccountID   string
		serviceAccountPASS string
		baseDomainName     string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"1", args{
			serverName: "", serviceAccountID: "", serviceAccountPASS: "", baseDomainName: "",
		}, true},
		{"2", args{
			serverName: ldapServerName, serviceAccountID: "", serviceAccountPASS: "", baseDomainName: "",
		}, true},
		{"3", args{
			serverName: ldapServerName, serviceAccountID: serviceAccountID, serviceAccountPASS: serviceAccountPASS, baseDomainName: "",
		}, true},
		{"4", args{
			serverName: ldapServerName, serviceAccountID: serviceAccountID, serviceAccountPASS: serviceAccountPASS, baseDomainName: baseDomainName,
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := pingLDAPServer(tt.args.serverName, tt.args.serviceAccountID, tt.args.serviceAccountPASS, tt.args.baseDomainName); (err != nil) != tt.wantErr {
				t.Errorf("pingLDAPServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
