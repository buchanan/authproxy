package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

var ImplicitGrant codeflow = "id_token"

type implicitGrantFlow struct {
	authFlow
}

func (F *implicitGrantFlow) AuthRequest() (err error) {
	// Check set-cookies
	agentAuthCookie := false
	for _, c := range F.cookies {
		if c.Name == "agent-authn-tx" {
			agentAuthCookie = true
		}
	}
	if !agentAuthCookie {
		return errors.New("Authorization redirect missing agent-authn-tx cookie")
	}
	return F.authFlow.AuthRequest()
}

func (F *implicitGrantFlow) AuthGrant() (err error) {
	// Check url redirect location
	if F.grantLocation.Hostname() != F.req.URL.Hostname() || F.grantLocation.EscapedPath() != "/agent/cdsso-oauth2" {
		logger.Warn(fmt.Sprintf("Unexpected redirect location. Got: %s Expected: %s/agent/cdsso-oauth2", F.grantLocation.String(), F.req.URL.Hostname()))
	}
	// Check for url fragments id_token & state
	idFrag, stateFrag := false, false
	for _, f := range strings.Split(F.grantLocation.Fragment, "&") {
		if strings.HasPrefix(f, "id_token") {
			idFrag = true
		}
		if strings.HasPrefix(f, "state") {
			stateFrag = true
		}
		if strings.HasPrefix(f, "access_token") {
			F.bearerToken = f[13:]
		}
	}
	if !idFrag {
		err = errors.New("Authorize redirect missing id_token url fragment")
	}
	if !stateFrag {
		err = errors.New("Authorize redirect missing state url fragment")
	}
	// Prepare authorization grant
	postBody := strings.NewReader(F.grantLocation.Fragment)

	F.authorizationGrant = &http.Request{
		Method: "POST",
		URL:    F.grantLocation,
		Header: make(http.Header),
		Host:   "",
		Body:   ioutil.NopCloser(postBody),
	}
	F.authorizationGrant.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return F.authFlow.AuthGrant()
}
