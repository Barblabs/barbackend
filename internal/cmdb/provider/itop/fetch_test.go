package itop

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"barbackend/internal/cmdb/provider/itop/rest"
)

var record = flag.Bool("record", false, "re-record testdata/fetch from the iTop named by ITOP_URL, ITOP_USER and ITOP_PASSWORD (source .env)")

type recording map[string]json.RawMessage

func recorded(t *testing.T, name string) *rest.Client {
	t.Helper()
	path := filepath.Join("testdata", "fetch", name+".json")
	var h http.Handler
	if *record {
		h = recorder(t, path)
	} else {
		h = replayer(t, path)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return rest.New(base, rest.BasicAuth("replay", "replay"), rest.Options{})
}

func replayer(t *testing.T, path string) http.Handler {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; run with -record against the local iTop to create it", err)
	}
	var rec recording
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, ok := rec[r.PostFormValue("json_data")]
		if !ok {
			t.Errorf("no recorded response for %s; re-record with -record", r.PostFormValue("json_data"))
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(res)
	})
}

func recorder(t *testing.T, path string) http.Handler {
	endpoint, user, password := os.Getenv("ITOP_URL"), os.Getenv("ITOP_USER"), os.Getenv("ITOP_PASSWORD")
	if endpoint == "" || user == "" || password == "" {
		t.Fatal("-record needs ITOP_URL, ITOP_USER and ITOP_PASSWORD")
	}
	var mu sync.Mutex
	rec := recording{}
	t.Cleanup(func() {
		raw, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := r.PostFormValue("json_data")
		form := url.Values{"json_data": {data}, "auth_user": {user}, "auth_pwd": {password}}
		res, err := http.PostForm(strings.TrimSuffix(endpoint, "/")+r.URL.RequestURI(), form)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = res.Body.Close() }()
		body, err := io.ReadAll(res.Body)
		if err != nil || res.StatusCode != http.StatusOK || !json.Valid(body) {
			t.Errorf("iTop answered %d %.200s: %v", res.StatusCode, body, err)
			return
		}
		mu.Lock()
		rec[data] = body
		mu.Unlock()
		_, _ = w.Write(body)
	})
}

func ptr(s string) *string { return &s }

func TestFetchSeededInstance(t *testing.T) {
	cis, lk, err := fetch(context.Background(), recorded(t, "seeded"))
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]ci{}
	var names []string
	for _, c := range cis {
		byName[c.Name] = c
		names = append(names, c.Name)
	}
	wantNames := []string{
		"Server1", "Server2", "Server3", "Server4", "Server5",
		"VM1", "VM2", "VM3", "VM4",
		"PC-ALICE", "PC-MIXED", "PC-OLD",
		"Router1", "Switch1", "Router2",
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Errorf("names = %v, want %v", names, wantNames)
	}

	want := []ci{
		{
			Key: "3", Class: "Server", Name: "Server3", Status: "production", Criticality: ptr("low"),
			Brand: "HPE", Model: "DL380", OSFamily: "vCenter Server", OSVersion: "2022",
			Contacts:  []contact{{ID: "18", Class: "Person"}, {ID: "53", Class: "Team"}},
			Instances: []instance{{Class: "Middleware", Name: "RabbitMQ", SoftwareID: "3"}},
		},
		{
			Key: "21", Class: "VirtualMachine", Name: "VM1", Status: "production", Criticality: ptr("medium"),
			OSFamily: "vCenter Server", OSVersion: "2022",
			Contacts:  []contact{{ID: "52", Class: "Team"}},
			Instances: []instance{{Class: "WebServer", Name: "Apache", SoftwareID: "0"}},
		},
		{
			Key: "33", Class: "PC", Name: "PC-MIXED", Status: "production",
			Brand: "Lenovo", Model: "ThinkPad T14", OSFamily: "Ubuntu", OSVersion: "22.04 LTS",
			Contacts:  []contact{{ID: "55", Class: "Person"}},
			Instances: []instance{},
		},
		{
			Key: "34", Class: "PC", Name: "PC-OLD", Status: "obsolete", Criticality: ptr("medium"),
			OSFamily: "Windows", OSVersion: "10",
			Contacts:  []contact{{ID: "54", Class: "Person"}},
			Instances: []instance{},
		},
		{
			Key: "40", Class: "NetworkDevice", Name: "Router2", Status: "production", Criticality: ptr("high"),
			Brand: "Cisco", Model: "Cisco 6500", IOSVersionID: "90",
			Contacts:  []contact{{ID: "46", Class: "Person"}},
			Instances: []instance{},
		},
	}
	for _, w := range want {
		if got := byName[w.Name]; !reflect.DeepEqual(got, w) {
			t.Errorf("%s:\n got %+v\nwant %+v", w.Name, got, w)
		}
	}

	wantLookups := lookups{
		persons: map[string]person{
			"5": {Email: "alice.milliat@customer.com"}, "8": {Email: "boris.vian@it.com"}, "18": {Email: "george.sand@it.com"},
			"46": {Email: "victor.hugo@it.com"}, "54": {Email: ""}, "55": {Email: "Test.MixedCase@IT.com"},
		},
		software: map[string]software{
			"1": {Name: "MySql", Version: "8"},
			"2": {Name: "Oracle DB engine", Version: "19c"},
			"3": {Name: "RabbitMQ", Version: "3.12.13"},
			"4": {Name: "Chrome", Version: "120.0.6099.109"},
			"5": {Name: "OpenSSH", Version: "9.6p1"},
			"6": {Name: "Apache HTTP Server", Version: "2.4.58"},
		},
		iosVersions: map[string]iosVersion{"90": {Brand: "Cisco", Name: "15.2(7)E"}},
	}
	if !reflect.DeepEqual(lk, wantLookups) {
		t.Errorf("lookups:\n got %+v\nwant %+v", lk, wantLookups)
	}
}

// iTop ships no SoftwareInstance class outside the kept ones, so the filter
// is tested on a hand-written object.
func TestDecodeCIKeepsOnlySoftwareComponentClasses(t *testing.T) {
	fields := `{"softwares_list": [
		{"finalclass": "DBServer", "name": "Postgres", "software_id": "7"},
		{"finalclass": "CustomInstance", "name": "Agent", "software_id": "8"}
	]}`
	c, err := decodeCI(rest.Object{Class: "Server", Key: "1", Fields: json.RawMessage(fields)}, []string{"softwares_list"})
	if err != nil {
		t.Fatal(err)
	}
	want := []instance{{Class: "DBServer", Name: "Postgres", SoftwareID: "7"}}
	if !reflect.DeepEqual(c.Instances, want) {
		t.Errorf("instances = %+v, want %+v", c.Instances, want)
	}
}

func TestDecodeRejectsMissingField(t *testing.T) {
	tests := []struct {
		name   string
		fields string
		want   string
	}{
		// iTop answers an output field the class lacks by dropping it, or with
		// an empty array when it was the only one.
		{"dropped field", `{"name": "Server1"}`, "Server::1 has no field status"},
		{"no fields", `[]`, "Server::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c ci
			o := rest.Object{Class: "Server", Key: "1", Fields: json.RawMessage(tt.fields)}
			if err := decode(o, []string{"name", "status"}, &c); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want a failure containing %q", err, tt.want)
			}
		})
	}
}
