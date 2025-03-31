package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	logrusWriter "github.com/sirupsen/logrus/hooks/writer"
)

var (
	logger    = logrus.New()
	debugFile = "/tmp/httpproxy"
	debugChan = make(chan []byte, 10)
	proxyLog  = log.New(logger.Writer(), "PROXY ERROR:", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lmsgprefix)
	amProxy   *httputil.ReverseProxy
	amServer  http.Server

	defaultTLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	defaultTransport = &http.Transport{
		TLSClientConfig: defaultTLSConfig.Clone(),
		Proxy:           http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
)

func ServeDebug(conn net.Conn) {
	for message := range debugChan {
		conn.SetDeadline(time.Now().Add(time.Minute))
		_, err := conn.Write(message)
		if err, ok := err.(net.Error); ok && err.Timeout() {
			conn.Close()
			return
		} else if err != nil {
			logger.Errorf("writing debug msg failed: %s", err)
			conn.Close()
			return
		}
	}
}

func HandleDebugConnections(l net.Listener) {
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Errorf("debug connection failed: %s", err)
		}
		go ServeDebug(conn)
	}
}

func init() {
	// Setup proxy
	amProxy = &httputil.ReverseProxy{
		Director:       filterRequest,
		Transport:      defaultTransport,
		ErrorLog:       proxyLog,
		ModifyResponse: filterResponse,
		ErrorHandler:   handleErrors,
	}
	amServer = http.Server{
		Addr:    ":9000",
		Handler: proxyHandler{},
		// Handler: amProxy,
		TLSConfig: defaultTLSConfig.Clone(),
	}
	// Setup logrus
	logger.SetOutput(ioutil.Discard)
	logger.SetLevel(logrus.TraceLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors: true,
	})
	if err := os.RemoveAll(debugFile); err != nil {
		logger.Fatal(err)
	}
	if l, err := net.Listen("unix", debugFile); err != nil {
		logger.Errorf("debug listen failed: %s", err)
	} else {
		go HandleDebugConnections(l)
	}
	logger.Hooks.Add(&logrusWriter.Hook{
		Writer: CircleWriter{
			Ch: debugChan,
		},
		LogLevels: []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel, logrus.WarnLevel, logrus.InfoLevel, logrus.DebugLevel, logrus.TraceLevel},
	})
	logger.Hooks.Add(&logrusWriter.Hook{
		Writer:    os.Stdout,
		LogLevels: []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel},
	})
}

type CircleWriter struct {
	io.Writer
	Ch chan []byte
}

func (w CircleWriter) Write(b []byte) (int, error) {
	for {
		select {
		case w.Ch <- b:
			return len(b), nil
		default:
			select {
			case <-w.Ch:
			default:
				go logger.Warn("Clear debug chan failed")
			}
		}
	}
}

func main() {
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		// We received an interrupt signal, shut down.
		if err := amServer.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	if err := amServer.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		logger.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
}

func filterRequest(req *http.Request) {
	if req.Method == "CONNECT" {
		logger.Println("Recieved CONNECT request. This should have already been caught! Stopping!")
		return
	}
	logger.Println("New request for", req)
	//TODO inject authentication token/cookies
	if err := authRequest(req); err != nil {
		switch err {
		case ErrMissingToken:
			logger.Println("Missing auth token for", req.URL.String())
		case ErrTokenGuessed:
			logger.Printf("Missing auth token for %s. Trying generic tokens for %s.\n", req.URL.String(), req.URL.Hostname())
		default:
			logger.Println("Unexpected error while authenticating request", err)
		}
	}
	logger.Println("Request with tokens", req)
}

func setCookie(req *http.Request, c *http.Cookie) {
	rc := req.Cookies()
	req.Header.Del("Cookie")
	req.AddCookie(c)
	for _, rcookie := range rc {
		if rcookie.Name != c.Name {
			req.AddCookie(rcookie)
		}
	}
}

var ErrMissingToken = errors.New("App token not found in cache")
var ErrTokenGuessed = errors.New("Incomplete token match found in cache")

func authRequest(req *http.Request) error {
	tokenMapLock.RLock()
	defer tokenMapLock.RUnlock()
	logger.Printf("TokenMap: %+v\n", tokenMap)
	tokenFound := false
	if tok, ok := tokenMap[url.URL{Host: req.URL.Hostname(), Path: req.URL.EscapedPath()}]; ok {
		for _, c := range tok.cookies {
			setCookie(req, c)
			tokenFound = true
		}
		if tok.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+tok.bearer)
		}
	}
	if !tokenFound {
		// Search with any tokens that have the same hostname
		for k, tok := range tokenMap {
			if k.Hostname() == req.URL.Hostname() {
				for _, c := range tok.cookies {
					setCookie(req, c)
					tokenFound = true
				}
			}
			if tok.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tok.bearer)
			}
		}
		if tokenFound {
			return ErrTokenGuessed
		} else {
			return ErrMissingToken
		}
	}
	return nil
}

// TODO should I base this map from the cookie domain/path instead of the request?
// var tokenMap = make(map[url.URL][]*http.Cookie)
var tokenMap = make(map[url.URL]token)
var tokenMapLock sync.RWMutex

var filteredDomains = []string{"login.changeme.com", "changeme.com", "id.changeme.com"}
var filteredNames = []string{"AMSession", "AMSessionAT", "AMSessionDev", "agent-authn-tx", "am-auth-jwt"}
var filteredURLs = []url.URL{
	url.URL{Host: "login.changeme.com", Path: "/sso/oauth2/authorize"},
	url.URL{Host: "login.changeme.com", Path: "/sso/json/realms/root/authenticate"},
	url.URL{Host: "id.changeme.com", Path: "/login"},
}

func authURL(U url.URL) bool {
	for _, f := range filteredURLs {
		if U.Hostname()+U.EscapedPath() == f.Hostname()+f.EscapedPath() {
			return true
		}
	}
	return false
}

func filterAuthCookies(resp *http.Response) {
	cookies := resp.Cookies()
	resp.Header.Del("Set-Cookie")

	for _, cookie := range cookies {
		if inSlice(filteredDomains, cookie.Domain) && inSlice(filteredNames, cookie.Name) {
			break
		}
		cookieString := cookie.String()
		if cookieString == "" {
			break
		}
		resp.Header.Add("Set-Cookie", cookieString)
	}
}

func inSlice(S interface{}, I interface{}) bool {
	if Sassert, good := S.([]string); good {
		for _, thing := range Sassert {
			if thing == I {
				return true
			}
		}
	}
	if Sassert, good := S.([]url.URL); good {
		for _, thing := range Sassert {
			if thing == I {
				return true
			}
		}
	}
	return false
}

var loginServers = []string{"login.changeme.com", "login-dev.changeme.com", "login-at.changeme.com"}

func filterResponse(resp *http.Response) (reterr error) {
	logger.Trace("Response received for:", resp.Request.URL.String())
	logger.Trace("filterResponse got:", resp)
	// Try and get location header if it exists we'll assume it's a redirect
	// If redirect location indicates that re-authentication or re-authorization
	// is needed then perform login and resend request
	// TODO check that a request doesn't get in a re-auth loop forever
	if redirURL, err := resp.Location(); err == nil {
		// if portSep := strings.LastIndexByte(redirURL, ":"); portSep != -1 {
		// 	redirURL = redirURL[:portSep]
		// }
		if inSlice(loginServers, redirURL.Hostname()) && redirURL.EscapedPath() == "/sso/oauth2/authorize" {
			// Check that our response includes the request. We can't perform authorization if we don't have this.
			if resp.Request == nil {
				return errors.New("Can't get auth token for response. Missing request")
			}
			// We don't need the body let's close it before we forget
			logger.Info("Auth needed for", resp.Request)
			ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			// Get auth token and place in map
			// Returns ErrAuthRequiredSuccess if successful
			reterr = getauthToken(resp)
		}
	}
	filterAuthCookies(resp)
	logger.Trace("Returning:", resp)
	return reterr
}

func getauthToken(resp *http.Response) error {
	flow, err := NewFlow(*resp)
	if err != nil {
		return err
	}
	if err := flow.AuthRequest(); err != nil {
		return err
	}
	if err := flow.AuthGrant(); err != nil {
		return err
	}
	tokenMapLock.Lock()
	defer tokenMapLock.Unlock()
	tokenMap[url.URL{Host: resp.Request.URL.Hostname(), Path: resp.Request.URL.EscapedPath()}] = flow.GetToken()
	// Forward response
	*resp = *flow.FinalResp()
	// Check that authorize didn't redirect us back to login
	return filterResponse(resp)
}

func handleErrors(w http.ResponseWriter, r *http.Request, err error) {
	if r.Method == "CONNECT" {
		logger.Println("Recieved CONNECT request hijacking connection. P.S. How did this happen?")
		hijackHTTPS(w, r)
		return
	}
	logger.Println("An unforgivable error occured", err)
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(err.Error()))
}
