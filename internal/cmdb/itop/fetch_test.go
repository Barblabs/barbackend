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

	"barbackend/internal/cmdb/itop/rest"
)

// fetch returns unexported types, so its tests sit inside the package.

var record = flag.Bool("record", false, "re-record testdata/fetch from the iTop named by ITOP_URL, ITOP_USER and ITOP_PASSWORD (source .env.itop)")

// recording maps each request's json_data to iTop's response. Requests are
// deterministic for a given instance, so a replay answers exactly them.
type recording map[string]json.RawMessage

// recorded serves the responses in testdata/fetch/name.json. With -record it
// forwards each request to the live iTop instead, authenticating with the
// credentials from the environment so none reach the recording, and rewrites
// the file when the test ends.
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
		byName[c.name] = c
		names = append(names, c.name)
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
			key: "3", class: "Server", name: "Server3", status: "production", criticality: ptr("low"),
			brand: "HPE", model: "DL380", osFamily: "vCenter Server", osVersion: "2022",
			contacts:  []contact{{id: "18", class: "Person"}, {id: "53", class: "Team"}},
			instances: []instance{{class: "Middleware", name: "RabbitMQ", softwareID: "3"}},
		},
		{
			key: "21", class: "VirtualMachine", name: "VM1", status: "production", criticality: ptr("medium"),
			osFamily: "vCenter Server", osVersion: "2022",
			contacts:  []contact{{id: "52", class: "Team"}},
			instances: []instance{{class: "WebServer", name: "Apache", softwareID: "0"}},
		},
		{
			key: "33", class: "PC", name: "PC-MIXED", status: "production",
			brand: "Lenovo", model: "ThinkPad T14", osFamily: "Ubuntu", osVersion: "22.04 LTS",
			contacts: []contact{{id: "55", class: "Person"}},
		},
		{
			key: "34", class: "PC", name: "PC-OLD", status: "obsolete", criticality: ptr("medium"),
			osFamily: "Windows", osVersion: "10",
			contacts: []contact{{id: "54", class: "Person"}},
		},
		{
			key: "40", class: "NetworkDevice", name: "Router2", status: "production", criticality: ptr("high"),
			brand: "Cisco", model: "Cisco 6500", iosVersionID: "90",
			contacts: []contact{{id: "46", class: "Person"}},
		},
	}
	for _, w := range want {
		if got := byName[w.name]; !reflect.DeepEqual(got, w) {
			t.Errorf("%s:\n got %+v\nwant %+v", w.name, got, w)
		}
	}

	// Team 52 and 53 are contacts too, but only Persons are looked up.
	wantLookups := lookups{
		emails: map[string]string{
			"5": "alice.milliat@customer.com", "8": "boris.vian@it.com", "18": "george.sand@it.com",
			"46": "victor.hugo@it.com", "54": "", "55": "Test.MixedCase@IT.com",
		},
		software: map[string]software{
			"1": {name: "MySql", version: "8"},
			"2": {name: "Oracle DB engine", version: "19c"},
			"3": {name: "RabbitMQ", version: "3.12.13"},
			"4": {name: "Chrome", version: "120.0.6099.109"},
			"5": {name: "OpenSSH", version: "9.6p1"},
			"6": {name: "Apache HTTP Server", version: "2.4.58"},
		},
		iosVersions: map[string]iosVersion{"90": {brand: "Cisco", version: "15.2(7)E"}},
	}
	if !reflect.DeepEqual(lk, wantLookups) {
		t.Errorf("lookups:\n got %+v\nwant %+v", lk, wantLookups)
	}
}

// iTop ships no SoftwareInstance class outside the kept ones, so the filter
// is tested on a hand-written document.
func TestNewCIKeepsOnlySoftwareComponentClasses(t *testing.T) {
	var doc ciDocument
	raw := `{"softwares_list": [
		{"finalclass": "DBServer", "name": "Postgres", "software_id": "7"},
		{"finalclass": "CustomInstance", "name": "Agent", "software_id": "8"}
	]}`
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	got := newCI(rest.Object{Class: "Server", Key: "1"}, doc).instances
	want := []instance{{class: "DBServer", name: "Postgres", softwareID: "7"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("instances = %+v, want %+v", got, want)
	}
}

func TestDecodeRejectsMissingField(t *testing.T) {
	tests := []struct {
		name   string
		fields string
	}{
		// iTop answers an output field the class lacks by dropping it, or with
		// an empty array when it was the only one.
		{"dropped field", `{"name": "Server1"}`},
		{"no fields", `[]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc ciDocument
			o := rest.Object{Class: "Server", Key: "1", Fields: json.RawMessage(tt.fields)}
			if err := decode(o, []string{"name", "status"}, &doc); err == nil {
				t.Error("err = nil, want a failure naming the missing field")
			}
		})
	}
}
