package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type codeflow string

type flow interface {
	AuthRequest() error // Perform authorization request and receive authorization grant // Execute auth grant to receive access token
	AuthGrant() error   // Perform authorization grant and receive access token
	GetToken() token
	FinalResp() *http.Response
}

type token struct {
	cookies []*http.Cookie
	bearer  string
}

type authFlow struct {
	flowtype           codeflow
	requestLocation    *url.URL
	authorizationGrant *http.Request
	grantLocation      *url.URL
	sessionToken       Token
	bearerToken        string
	cookies            []*http.Cookie
	req                *http.Request
	resp               *http.Response
	accessToken        []*http.Cookie
}

func (F authFlow) GetToken() token {
	return token{
		cookies: F.accessToken,
		bearer:  F.bearerToken,
	}
}
func (F authFlow) FinalResp() *http.Response {
	return F.resp
}

func NewFlow(resp http.Response) (Flow flow, err error) {
	var flowtype codeflow
	var respRedir *url.URL
	if respRedir, err = resp.Location(); respRedir != nil {
		if respRedir.Query().Get("response_mode") == "form_post" {
			urlQuery := respRedir.Query()
			urlQuery.Del("response_mode")
			respRedir.RawQuery = urlQuery.Encode()
		}
		flowtype = codeflow(respRedir.Query().Get("response_type"))
	} else {
		return nil, err
	}
	//Remove response_mode=form_post from the url query
	Token := Token{
		URL: respRedir.Hostname(),
	}
	if Token.GetToken() == false {
		err = errors.New("Failed to get AMSession")
	}
	var Jar []*http.Cookie
	Jar = append(Jar, resp.Request.Cookies()...)
	Jar = append(Jar, resp.Cookies()...)

	switch flowtype {
	case ImplicitGrant:
		Flow = &implicitGrantFlow{
			authFlow{
				flowtype:        flowtype,
				requestLocation: respRedir,
				sessionToken:    Token,
				cookies:         Jar,
				req:             resp.Request, // This is checked to be non-nil in filterResponse()
			}}
	case CodeGrant:
		Flow = &codeGrantFlow{
			authFlow{
				flowtype:        flowtype,
				requestLocation: respRedir,
				sessionToken:    Token,
				cookies:         Jar,
				req:             resp.Request, // This is checked to be non-nil in filterResponse()
			}}
	default:
		err = errors.New("Unrecognized code flow")
	}
	return Flow, err
}

func (F *authFlow) AuthRequest() (err error) {
	// Perform authorization request
	authorizeRequest := &http.Request{
		Method: "GET",
		URL:    F.requestLocation,
		Header: make(http.Header),
		Host:   "",
	}
	var authorizeGrant *http.Response
	logger.Info("Performing AuthRequest:", authorizeRequest)
	authorizeGrant, err = authenticate(authorizeRequest, F.sessionToken)
	if err == nil {
		ioutil.ReadAll(authorizeGrant.Body)
		authorizeGrant.Body.Close()
		F.grantLocation, err = authorizeGrant.Location()
	}
	return err
}

func (F *authFlow) AuthGrant() (err error) {
	// Add cookies
	for _, c := range F.cookies {
		F.authorizationGrant.AddCookie(c)
	}
	logger.Info("Performing AuthorizeGrant:", F.authorizationGrant)
	F.resp, err = authenticate(F.authorizationGrant, F.sessionToken)
	if err != nil {
		return err
	}
	logger.Info("Got FinalResp:", F.resp)
	if respRedir, lookuperr := F.resp.Location(); lookuperr == nil {
		if respRedir.Hostname() != F.req.URL.Hostname() || respRedir.EscapedPath() != F.req.URL.EscapedPath() {
			logger.Warning(fmt.Sprintf("Unexpected redirect location. Got: %s Expected: %s", respRedir.String(), F.req.URL.String()))
		}
	} else {
		logger.Warning(fmt.Sprintf("Expected redirect back to application Got: %+v\n", F.resp))
		respBody, _ := ioutil.ReadAll(F.resp.Body)
		F.resp.Body.Close()
		logger.Trace(fmt.Sprintf("%s", respBody))
		F.resp.Body = ioutil.NopCloser(bytes.NewReader(respBody))
	}
	F.accessToken = F.resp.Cookies()
	if len(F.accessToken) == 0 {
		logger.Error("No cookies recieved. Expected authorization response cookie. Token expired?")
		logger.Info("Lets try adding all cookies retrived this session.")
		F.accessToken = F.cookies
	}
	// Set resp
	F.resp.Header.Del("Set-Cookie")
	return err
}

//If T (Token) is blank then the cached token will be used or if Token is set and maches cached token then a new token will be retrieved.
//If you pass in a Token it is assumed to be bad
//TODO don't add cookie if it already exists OR replace cookie if it already exists
func authenticate(req *http.Request, T Token) (*http.Response, error) {
	//Check if request is already authenticated
	//TODO pass Environments instead of Tokens
	setCookie(req, &T.Token)

	logger.Info(fmt.Sprintf("Performing: %+v\n", req))

	//Re-perform request
	newctx, cancel := context.WithTimeout(req.Context(), time.Second*30)
	defer cancel()
	authresp, err := defaultTransport.RoundTrip(req.WithContext(newctx))
	if err != nil {
		logger.Error("Error while performing authenticated request", err.Error())
		return nil, err
	}
	logger.Info(fmt.Sprintf("Got: %+v\n", authresp))
	return authresp, nil
}
