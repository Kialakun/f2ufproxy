package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
)

type Proxy struct {
	UpstreamURL  string
	UpstreamUser string
	UpstreamPass string
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle CONNECT method (HTTPS tunneling)
	if r.Method == http.MethodConnect {
		p.handleHTTPS(w, r)
		return
	}

	// Handle regular HTTP requests
	p.handleHTTP(w, r)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Create HTTP client with upstream proxy transport
	var client *http.Client

	if p.UpstreamURL != "" {
		upstreamURL, err := url.Parse(p.UpstreamURL)
		if err != nil {
			http.Error(w, "Invalid upstream proxy URL", http.StatusInternalServerError)
			return
		}

		transport := &http.Transport{
			Proxy: http.ProxyURL(upstreamURL),
		}
		client = &http.Client{Transport: transport}

		// Add Proxy-Authorization header for upstream proxy
		if p.UpstreamUser != "" && p.UpstreamPass != "" {
			auth := base64.StdEncoding.EncodeToString([]byte(p.UpstreamUser + ":" + p.UpstreamPass))
			r.Header.Set("Proxy-Authorization", "Basic "+auth)
		}
	} else {
		client = &http.Client{}
	}

	// Modify the request to remove the proxy headers
	r.RequestURI = ""
	r.URL.Scheme = "http"
	if r.TLS != nil {
		r.URL.Scheme = "https"
	}

	// Forward the request
	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers from target server to client
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Copy body from target server to client
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error copying response body: %v", err)
	}
}

func (p *Proxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	var destConn net.Conn
	var err error

	if p.UpstreamURL != "" {
		// Connect to upstream proxy instead of target
		upstreamURL, err := url.Parse(p.UpstreamURL)
		if err != nil {
			http.Error(w, "Invalid upstream proxy URL", http.StatusInternalServerError)
			return
		}
		destConn, err = net.Dial("tcp", upstreamURL.Host)
	} else {
		// Direct connection to target
		destConn, err = net.Dial("tcp", r.Host)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	// Hijack the connection to get raw TCP access
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// If forwarding through upstream proxy, send CONNECT with auth
	if p.UpstreamURL != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(p.UpstreamUser + ":" + p.UpstreamPass))
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
			r.Host, r.Host, auth)
		_, err := destConn.Write([]byte(connectReq))
		if err != nil {
			log.Printf("Error sending CONNECT to upstream: %v", err)
			return
		}

		// Read and discard the 200 response
		buf := make([]byte, 4096)
		destConn.Read(buf)
	}

	// Send 200 OK to client
	w.WriteHeader(http.StatusOK)

	// Start bidirectional copy
	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}

func main() {
	proxy := &Proxy{
		UpstreamURL:  "http://upstream-proxy:3128",
		UpstreamUser: "proxyuser",
		UpstreamPass: "proxypass",
	}

	server := &http.Server{
		Addr:    ":8081",
		Handler: proxy,
	}

	fmt.Println("Starting proxy server on :8081")
	fmt.Printf("Forwarding through upstream: %s\n", proxy.UpstreamURL)
	log.Fatal(server.ListenAndServe())
}
