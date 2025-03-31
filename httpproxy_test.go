package main

// https://blog.questionable.services/article/testing-http-handlers-go/
// Tip: make strings like application/json or Content-Type package-level
// constants, so you don’t have to type (or typo) them over and over. A
// typo in your tests can cause unintended behaviour, becasue you’re not
// testing what you think you are.
// You should also make sure to test not just for success, but for failure
// too: test that your handlers return errors when they should
// (e.g. a HTTP 403, or a HTTP 500).

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

var debugLog *log.Logger

func init() {
	if logfile, err := os.Create("debug.log"); err == nil {
		debugLog = log.New(logfile, "", log.LstdFlags)
	} else {
		log.Println("Unable to create debug.log", err)
	}
}

func compareBody(a, b io.ReadCloser) (bool, string) {
	adata, err := ioutil.ReadAll(a)
	if err != nil {
		return false, err.Error()
	}
	bdata, err := ioutil.ReadAll(b)
	if err != nil {
		return false, err.Error()
	}
	if bytes.Equal(adata, bdata) {
		return true, ""
	} else {
		debugLog.Printf("Unmatched response body\nA:\t%s\n-----\nB:\t%s\n-----\n", adata, bdata)
	}
	return false, "body unequal"
}

func proxyGet(url string, follow bool) (*http.Response, error) {
	C := http.Client{
		Transport: proxyTrip{},
	}
	if !follow {
		C.CheckRedirect = func(r *http.Request, v []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return C.Do(req)
	// rr := httptest.NewRecorder()
	// proxyHandler{}.ServeHTTP(rr, req)
	// proxyresp := rr.Result()
	// return proxyresp, nil
}

type proxyTrip struct {
	http.Transport
}

func (pt proxyTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	rr := httptest.NewRecorder()
	proxyHandler{}.ServeHTTP(rr, req)
	proxyresp := rr.Result()
	return proxyresp, nil
}

func TestNoAuthRequest(t *testing.T) {
	defresp, err := http.Get("https://www.changeme.com/index.html")
	if err != nil {
		t.Fatal(err)
	}
	proxyresp, err := proxyGet("https://www.changeme.com/index.html", false)
	if err != nil {
		t.Fatal(err)
	}

	if proxyresp.Status != defresp.Status {
		t.Error("Proxy response status mismatch")
	}
	if proxyresp.ContentLength != defresp.ContentLength {
		t.Fatal("Proxy response content length doesn't match")
	}
	if same, msg := compareBody(proxyresp.Body, defresp.Body); !same {
		t.Error("Proxy response body does not match")
		t.Log(msg)
	}
}

func TestResponseLeakCredentials(t *testing.T) {
	proxyresp, err := proxyGet("https://sunrise.changeme.com/sunrise/", false)
	if err != nil {
		t.Fatal(err)
	}
	// TODO check that a valid/expected response was recieved
	for _, c := range proxyresp.Cookies() {
		switch c.Name {
		case "AMSession":
			t.Error("AMSession leaked")
		case "AMSessionDev":
			t.Error("AmSessionDev leaked")
		case "AMSessionAT":
			t.Error("AMSessionAT leaked")
		case "am-auth-jwt":
			t.Error("am-auth-jwt leaked")
		}
	}
}

func TestImplicitGrantFlow(t *testing.T) {
	proxyresp, err := proxyGet("https://sunrise.changeme.com/sunrise/", true)
	if err != nil {
		t.Fatal(err)
	}

	if proxyresp.StatusCode != 200 {
		t.Errorf("Proxy response: %s\n", proxyresp.Status)
	}
	if body, err := ioutil.ReadAll(proxyresp.Body); err != nil {
		t.Error(err)
	} else if !bytes.Contains(body, []byte("Sunrise System")) {
		t.Error("Proxy response body missing exptected string Sunrise System")
	}
}

func TestCodeGrantFlow(t *testing.T) {
	proxyresp, err := proxyGet("https://avr.changeme.com/", true)
	if err != nil {
		t.Fatal(err)
	}

	if proxyresp.StatusCode != 200 {
		t.Errorf("Proxy response: %s\n", proxyresp.Status)
	}
	if body, err := ioutil.ReadAll(proxyresp.Body); err != nil {
		t.Error(err)
	} else if !bytes.Contains(body, []byte("ShinyProxy")) {
		t.Error("Proxy response body missing exptected string ShinyProxy")
	}
}

// Test that expired session is detected and new credentials are grabbed
// Test login function get new amsession
// Test logout function expires a session
// Test that AMSession token is validated before use / Here we only create a new token we don't call login directly
func TestSessionRotation(t *testing.T) {
	RotateSession(&C.Prod, t)
	RotateSession(&C.Dev, t)
	RotateSession(&C.Test, t)
}

func RotateSession(E *Environment, t *testing.T) {
	T := Token{
		URL: E.Host,
	}
	if !T.GetToken() {
		t.Errorf("Could not get %s session", E.Name)
		return
	}
	oldToken := T.Token.Value
	if !updateSessionInfo(E) {
		t.Errorf("Could not get valid %s session", E.Name)
		return
	}
	logoutSession(*E)
	if updateSessionInfo(E) {
		t.Errorf("Logout %s session failed", E.Name)
		return
	}
	if !T.GetToken() {
		t.Errorf("Could not get new %s session", E.Name)
		return
	}
	if !updateSessionInfo(E) {
		t.Errorf("Could not get a new valid %s session", E.Name)
		return
	}
	if T.Token.Value == oldToken {
		t.Errorf("Failed to get new %s token", E.Name)
		return
	}
}

// Test that login error is logged appropriatly
func TestBadCredentials(t *testing.T) {
	E := Environment{Name: "Prod", Host: "login.changeme.com", CookieName: "AMSession", Username: "changeme", Password: "badPassword"}
	if loginSession(&E) {
		t.Error("Login with bad password returned successful")
	}
	if updateSessionInfo(&E) {
		t.Error("Invalid session marked as valid")
	}
	logoutSession(E)
}

func TestCloseFileHandles(t *testing.T) {

}
