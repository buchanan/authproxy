package main

import (
	"net/http"
)

var CodeGrant codeflow = "code"

type codeGrantFlow struct {
	authFlow
}

func (F *codeGrantFlow) AuthGrant() (err error) {
	// Do i need to check url redirect location?

	// Do I need to check for url fragments id_token & state

	//Prepare authorization grant
	F.authorizationGrant = &http.Request{
		Method: "GET",
		URL:    F.grantLocation,
		Header: make(http.Header),
		Host:   "",
	}

	return F.authFlow.AuthGrant()
}
