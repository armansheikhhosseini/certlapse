package ctlog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestHostnames(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = w.Write([]byte(`[
			{"name_value": "www.example.com\nexample.com"},
			{"name_value": "API.example.com"},
			{"name_value": "*.example.com\n*.dev.example.com"},
			{"name_value": "shop.example.com\nshop.other.org"},
			{"name_value": "www.example.com"}
		]`))
	}))
	defer srv.Close()

	names, wildcards, err := Client{BaseURL: srv.URL + "/"}.Hostnames(context.Background(), "Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "example.com", "shop.example.com", "www.example.com"}
	if !slices.Equal(names, want) || wildcards != 2 {
		t.Errorf("names = %v, wildcards = %d; want %v, 2", names, wildcards, want)
	}
	if query != "exclude=expired&output=json&q=%25.example.com" {
		t.Errorf("query = %q", query)
	}
}

func TestHostnamesRetriesServerErrors(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "busy", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`[{"name_value": "a.example.com"}]`))
	}))
	defer srv.Close()

	names, _, err := Client{BaseURL: srv.URL + "/", Retries: 1, Backoff: time.Millisecond}.Hostnames(context.Background(), "example.com")
	if err != nil || calls != 2 || !slices.Contains(names, "a.example.com") {
		t.Errorf("names = %v, err = %v, calls = %d; want a.example.com after 2 calls", names, err, calls)
	}
}

func TestHostnamesDoesNotRetryClientErrors(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	defer srv.Close()

	if _, _, err := (Client{BaseURL: srv.URL + "/"}).Hostnames(context.Background(), "example.com"); err == nil || calls != 1 {
		t.Errorf("err = %v, calls = %d; want an error after 1 call", err, calls)
	}
}

func TestHostnamesRejectsInvalidDomains(t *testing.T) {
	for _, d := range []string{"", "%.example.com", "*.example.com", "a b.com"} {
		if _, _, err := (Client{}).Hostnames(context.Background(), d); err == nil {
			t.Errorf("Hostnames(%q) succeeded, want an error", d)
		}
	}
}
