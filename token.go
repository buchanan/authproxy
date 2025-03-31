package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

var (
	errorRetryInterval time.Duration
	argVerbose         *bool  = new(bool)
	argDebug           *bool  = new(bool)
	apiVersion         string = "resource=2.1, protocol=1.0"
)

type Environment struct {
	Name          string
	Host          string
	CookieName    string
	Username      string
	Password      string
	Token         http.Cookie
	Expiration    time.Time
	LastErrorTime time.Time
	L             sync.RWMutex
}

type Cache struct {
	L    sync.RWMutex
	Prod Environment
	Dev  Environment
	Test Environment
}

var C Cache = Cache{
	Prod: Environment{Name: "Prod", Host: "login.changeme.com", CookieName: "AMSession", Username: "changeme", Password: "changeme"},
	Dev:  Environment{Name: "Dev", Host: "login-dev.changeme.com", CookieName: "AMSessionDev", Username: "changeme", Password: "changeme"},
	Test: Environment{Name: "AT", Host: "login-at.changeme.com", CookieName: "AMSessionAT", Username: "changeme", Password: "changeme"},
}

type Token struct {
	URL   string
	Token http.Cookie
}

func (T Token) newToken() bool {
	C.L.Lock()
	defer C.L.Unlock()
	//If cached token is blank or matched previously used token (cached token may have been updated while we were blocked)
	cachedToken := T.getTokenUnsafe().Value
	if cachedToken == "" || cachedToken == T.Token.Value {
		switch T.URL {
		case C.Prod.Host:
			valid := loginSession(&C.Prod)
			if !valid {
				logger.Error("Error establishing Prod session.")
				C.Prod.LastErrorTime = time.Now()
				return false
			}
		case C.Dev.Host:
			valid := loginSession(&C.Dev)
			if !valid {
				logger.Error("Error establishing Dev session.")
				C.Dev.LastErrorTime = time.Now()
				return false
			}
		case C.Test.Host:
			valid := loginSession(&C.Test)
			if !valid {
				logger.Error("Error establishing Test session.")
				C.Test.LastErrorTime = time.Now()
				return false
			}
		default:
			logger.Error("Error no environments configured for", T.URL)
		}
	}
	return true
}

// Get new tokens until token in cache is different from the one we have
func (T *Token) GetToken() bool {
	//Get cached token (if cached token is expired or invalid response will be blank)
	t := T.getTokenSafe()
	//If cached token is blank or equal to previously used (failed) token
	if t.Value == "" || t.Value == T.Token.Value {
		logger.Debug("Requesting new token")
		//Request new token
		if T.newToken() {
			//Get new cached token
			t = T.getTokenSafe()
		} else {
			return false
		}
	}
	//Return cached token
	T.Token = t
	return true
}

func (T Token) getTokenSafe() http.Cookie {
	//Acquire readlock
	C.L.RLock()
	defer C.L.RUnlock()
	return T.getTokenUnsafe()
}

func cleanup(Tr *http.Transport) {
	T := time.NewTicker(time.Minute)
	for _ = range T.C {
		logger.Info("Cleaning up connections")
		Tr.CloseIdleConnections()
	}
}

func (T Token) getTokenUnsafe() http.Cookie {
	switch T.URL {
	case C.Prod.Host:
		//Check if cached token is expired
		valid := updateSessionInfo(&C.Prod)
		if C.Prod.Expiration.After(time.Now()) && valid {
			return C.Prod.Token
		}
	case C.Dev.Host:
		valid := updateSessionInfo(&C.Dev)
		if C.Dev.Expiration.After(time.Now()) && valid {
			return C.Dev.Token
		}
	case C.Test.Host:
		valid := updateSessionInfo(&C.Test)
		if C.Test.Expiration.After(time.Now()) && valid {
			return C.Test.Token
		}
	default: //Placeholder
	}
	return http.Cookie{}
}

func loginSession(session *Environment) bool {
	if session.LastErrorTime.Add(errorRetryInterval).After(time.Now()) {
		logger.Debug(fmt.Sprintf("Skipping login attempt for %s due to previous error", session.Name))
		return false
	}

	if valid := updateSessionInfo(session); valid {
		logger.Debug(fmt.Sprintf("Existing session for %s is still valid", session.Name))
		return true
	} else {
		logger.Debug(fmt.Sprintf("Existing session for %s is invalid", session.Name))
		logoutSession(*session)
	}

	logger.Info(fmt.Sprintf("Creating new session for %s", session.Name))
	logger.Debug(fmt.Sprintf("Calling authenticate for %s", session.Name))

	var reqUrl = fmt.Sprintf("https://%s/sso/json/realms/root/authenticate?service=PasswordOnly&authIndexType=service&authIndexValue=PasswordOnly", session.Host)

	if req, err := http.NewRequest("POST", reqUrl, nil); err == nil {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept-API-Version", apiVersion)
		req.Header.Add("X-OpenAM-Username", session.Username)
		req.Header.Add("X-OpenAM-Password", session.Password)
		if resp, err := new(http.Client).Do(req); err == nil {
			if resp.StatusCode != 200 {
				logger.Debug(fmt.Sprintf("Login response generated code %d", resp.StatusCode))
			}
			message, err := ioutil.ReadAll(resp.Body)
			//_, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				logger.Debug(fmt.Sprintf("Unable to read response body %s\n", err.Error()))
				return false
			} else {
				//TODO check if login is prompting for security questions or rsa key...
				logger.Debug(fmt.Sprintf("Login response body %s\n", string(message)))
			}
			for _, c := range resp.Cookies() {
				logger.Debug(fmt.Sprintf("Login response cookies %+v\n", c))
				if c.Name == session.CookieName {
					logger.Debug(fmt.Sprintf("Found new %s session. %s\n", session.Name, c.Value))
					session.Token = *c
				}
			}
		} else {
			logger.Info(fmt.Sprintf("While getting %s session:", session.Name), err.Error())
			//go log.UnwrapError(err)
			return false
		}
	}
	logger.Debug(fmt.Sprintf("New %s session: %+v\n", session.Name, session.Token))
	if updateSessionInfo(session) {
		logger.Info(fmt.Sprintf("Session for %s is valid with expiration time %v", session.Name, session.Expiration))
		return true
	} else {
		logger.Warning(fmt.Sprintf("Error validating new %s session", session.Name))
		return false
	}
}

func logoutSession(session Environment) {
	logger.Info(fmt.Sprintf("Logging out session %s", session.Name))
	logger.Debug(fmt.Sprintf("Calling logout for %s", session.Name))

	var reqUrl = fmt.Sprintf("https://%s/sso/json/sessions/?_action=logout", session.Host)
	if req, err := http.NewRequest("POST", reqUrl, nil); err == nil {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept-API-Version", apiVersion)
		req.AddCookie(&session.Token)
		resp, err := new(http.Client).Do(req)
		if err != nil {
			logger.Debug("Unable to logout session", err.Error())
		} else {
			if resp.StatusCode != 200 {
				logger.Debug("While logging out session received response code", resp.Status)
			}
			var logoutResponse struct {
				Result string `json:"result"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&logoutResponse); err != nil {
				logger.Debug("Unable to parse logout message", err.Error())
			}
			if logoutResponse.Result != "Successfully logged out" {
				logger.Debug(fmt.Sprintf("Recieved message '%s' in response to logout. Expected message Successfully logged out", logoutResponse.Result))
			}
		}
	}
}

func updateSessionInfo(session *Environment) bool {
	logger.Debug(fmt.Sprintf("Checking session: %s", session.Name))
	defer logger.Debug(fmt.Sprintf("Done checking session: %s", session.Name))

	var sessionInfo struct {
		Username             string          `json:"username"`
		UniversalId          string          `json:"universalId"`
		Realm                string          `json:"realm"`
		LatestAccessTime     string          `json:"latestAccessTime"`
		MaxIdleExpiration    string          `json:"maxIdleExpirationTime"`
		MaxSessionExpiration string          `json:"maxSessionExpirationTime"`
		Properties           json.RawMessage `json:"properties"`
	}

	logger.Debug(fmt.Sprintf("Making getSessionInfo call for %s", session.Name))

	var reqUrl = fmt.Sprintf("https://%s/sso/json/sessions/?_action=getSessionInfo&tokenId=%s", session.Host, session.Token.Value)
	if req, err := http.NewRequest("POST", reqUrl, nil); err == nil {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept-API-Version", apiVersion)
		req.AddCookie(&session.Token)
		if resp, err := new(http.Client).Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 401 {
				logger.Debug(fmt.Sprintf("While verifying %s session received 401 response", session.Name))
				message, err := ioutil.ReadAll(resp.Body)
				// _, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					logger.Debug(fmt.Sprintf("Unable to read response body %s\n", err.Error()))
					return false
				} else {
					logger.Info(string(message))
					return false
				}
			}
			if err := json.NewDecoder(resp.Body).Decode(&sessionInfo); err != nil {
				logger.Debug(fmt.Sprintf("Unable to verify %s session", session.Name))
				logger.Debug(fmt.Sprintf("Unable to read response body %s\n", err.Error()))
				return false
			}
			if date, err := time.Parse(time.RFC3339, sessionInfo.MaxSessionExpiration); err != nil {
				logger.Debug(fmt.Sprintf("Unable to verify %s session", session.Name))
				logger.Debug("Unable to parse session expiration time", err.Error())
				logger.Debug(fmt.Sprintf("%+v\n", resp))
				logger.Debug(fmt.Sprintf("%+v\n", sessionInfo))
				return false
			} else {
				if time.Now().After(date) {
					logger.Info(fmt.Sprintf("Session %s older than MaxSessionExpiration", session.Name))
					return false
				}
				session.Expiration = date
			}
		} else {
			logger.Debug(fmt.Sprintf("While verifying %s session:", session.Name), err.Error())
			//go log.UnwrapError(err)
			return false
		}
	}

	logger.Debug(fmt.Sprintf("Session %s for %s will expire in %s", session.Name, session.Username, (session.Expiration.Sub(time.Now()))))
	return true
}
