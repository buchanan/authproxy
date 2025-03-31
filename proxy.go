package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"syscall"
)

type proxyConn struct {
	net.Listener
	conn chan net.Conn
}

func newProxyConn(C net.Conn) proxyConn {
	P := proxyConn{
		conn: make(chan net.Conn, 10),
	}
	P.conn <- C
	return P
}

func (c proxyConn) Accept() (net.Conn, error) {
	nextConn, open := <-c.conn
	if open {
		return nextConn, nil
	}
	return nil, syscall.EINVAL
}

func (c proxyConn) Close() error {
	close(c.conn)
	return nil
}

func (c proxyConn) Addr() net.Addr {
	return nil
}

type proxyHandler struct {
	http.Handler
	mitmProxy
}

type mitmProxy struct {
	URL        *url.URL
	RequestURI string
	Jar        *cookiejar.Jar
}

func hijackHTTPS(w http.ResponseWriter, r *http.Request) {
	// TODO test connection to dest host before creating TLS session
	hij, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}

	hijackConn, _, e := hij.Hijack()
	if e != nil {
		panic("Cannot hijack connection " + e.Error())
	}
	// defer hijackConn.Close()

	hijackConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	logger.Println("Assuming CONNECT is TLS, mitm proxying it")
	// this goes in a separate goroutine, so that the net/http server won't think we're
	// still handling the request even after hijacking the connection. Those HTTP CONNECT
	// request can take forever, and the server will be stuck when "closed".
	// TODO: Allow Server.Close() mechanism to shut down this connection as nicely as possible
	tlsConfig := defaultTLSConfig.Clone()
	if CA != nil {
		var err error
		tlsConfig, err = CA(r.URL.Host)
		if err != nil {
			httpError(hijackConn, err)
			return
		}
	}
	//TODO: cache connections to the remote website
	rawClientTLS := tls.Server(hijackConn, tlsConfig)
	if err := rawClientTLS.Handshake(); err != nil {
		logger.Printf("Cannot handshake client %v %v", r.Host, err)
		return
	}
	//defer rawClientTls.Close()

	http.Serve(newProxyConn(rawClientTLS), proxyHandler{
		mitmProxy: mitmProxy{
			URL:        r.URL,
			RequestURI: r.RequestURI,
		}})
}

func (H proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		hijackHTTPS(w, r)
		return
	}
	logger.Printf("%+v\n", r)
	if H.mitmProxy.URL != nil {
		r.URL.Scheme = "https"
		r.URL.Host = H.mitmProxy.URL.Host
		r.RequestURI = H.mitmProxy.RequestURI
	}
	logger.Printf("Handing off to reverseproxy: %+v\n", r)
	amProxy.ServeHTTP(w, r)
}
