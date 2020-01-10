package ldap

import (
	"reflect"
	"testing"
)

func TestLDAPAPI(t *testing.T) {
	var (
	// test1arr = []Response{}
	)
	type args struct {
		subjectID string
	}
	tests := []struct {
		name    string
		args    args
		want    []Response
		want1   int
		wantErr bool
	}{
		{"1", args{subjectID: ""}, nil, 500, true},
		// {"2", args{subjectID: "cn156420"}, nil, 200, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := LDAP(tt.args.subjectID)
			if (err != nil) != tt.wantErr {
				t.Errorf("LDAP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LDAP() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("LDAP() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_parseLDAPAPImessageMemberOfRoles(t *testing.T) {
	var (
		r1 = Response{
			DN:       "",
			Controls: nil,
			CN:       "",
			MemberOf: []string{"cn=a", "cn=b"},
		}
		r2 = Response{
			DN:       "",
			Controls: nil,
			CN:       "",
			MemberOf: []string{"cn=b", "cn=c"},
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
			got, err := parseResponseOfMemberOfRoles(tt.args.arr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResponseOfMemberOfRoles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseResponseOfMemberOfRoles() = %v, want %v", got, tt.want)
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

func Test_makeAPIRequest(t *testing.T) {
	type args struct {
		method      string
		url         string
		requestBody []byte
		auth        string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		want1   int
		wantErr bool
	}{
		{"1", args{
			method:      "GET",
			url:         "www.google.com",
			requestBody: []byte{},
			auth:        "",
		}, nil, 500, true},
		{"2", args{
			method:      "GET",
			url:         "www.google.com",
			requestBody: nil,
			auth:        "",
		}, nil, 500, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := makeAPIRequest(tt.args.method, tt.args.url, tt.args.requestBody, tt.args.auth)
			if (err != nil) != tt.wantErr {
				t.Errorf("makeAPIRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("makeAPIRequest() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("makeAPIRequest() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
