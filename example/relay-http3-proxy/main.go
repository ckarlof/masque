package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	masque "github.com/invisv-privacy/masque"
	masqueH3 "github.com/invisv-privacy/masque/http3"
)

// Command line flags
var (
	listenPort       = flag.Int("listenPort", 32190, "Port to listen on for HTTP CONNECT requests")
	listenStatusPort = flag.Int("listenStatusPort", 32323, "Port to listen on for proxy status requests")
	auth             = flag.String("auth", "", "Authentication for proxy access, in format username:password")
	invisvRelay      = flag.String("invisvRelay", "", "Invisv Relay server to connect to")
	invisvRelayPort  = flag.Int("invisvRelayPort", 443, "Invisv Relay server port to connect to")
	token            = flag.String("token", "", "Invisv Relay authentication token")
	insecure         = flag.Bool("insecure", false, "Ignore check of Relay server certificate?")
	certDataFile     = flag.String("certDataFile", "", "File containing cert data for TLS cert pinning")
	verbose          = flag.Bool("verbose", false, "Whether to log at DEBUG level")
)

var relayClient *masqueH3.Client

func transfer(dst io.WriteCloser, src io.ReadCloser, wg *sync.WaitGroup, logger *slog.Logger) {
	defer wg.Done()
	n, err := io.Copy(dst, src)
	if err != nil {
		if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe) {
			logger.Debug("Connection closed during io.Copy", "err", err, "n", n)
		} else {
			logger.Error("Error during io.Copy", "err", err, "n", n)
		}
	} else {
		logger.Debug("Successfully transferred bytes", "n", n)
	}
}

// handleConnect opens a MASQUE-over-HTTP3 TCP stream to req.URL.Host
func handleConnect(c net.Conn, req *http.Request, logger *slog.Logger) io.ReadWriteCloser {
	logger = logger.With("req", req)
	disallowed := &http.Response{StatusCode: http.StatusUnauthorized, ProtoMajor: 1, ProtoMinor: 1}

	// validate port
	_, port, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		logger.Error("Invalid host:port", "err", err)
		disallowed.Write(c)
		c.Close()
		return nil
	}
	portInt, err := strconv.Atoi(port)
	if err != nil || masque.IsDisallowedPort(uint16(portInt)) {
		logger.Error("Disallowed or invalid port", "port", port)
		disallowed.Write(c)
		c.Close()
		return nil
	}

	// open TCP stream via HTTP/3 MASQUE
	stream, err := relayClient.CreateTCPStream(req.URL.Host)
	if err != nil {
		logger.Error("Failed to create MASQUE TCP stream", "err", err)
		disallowed.Write(c)
		c.Close()
		return nil
	}
	return stream
}

func handleReq(conn net.Conn, logger *slog.Logger) {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		logger.Debug("Failed to read HTTP request", "err", err)
		return
	}
	logger = logger.With("remote", conn.RemoteAddr(), "req", req)

	// proxy authentication
	if *auth != "" {
		authHdr := req.Header.Get("Proxy-Authorization")
		if authHdr == "" {
			resp := &http.Response{StatusCode: http.StatusProxyAuthRequired, ProtoMajor: 1, ProtoMinor: 1}
			resp.Write(conn)
			conn.Close()
			return
		}
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(*auth))
		if authHdr != expected {
			resp := &http.Response{StatusCode: http.StatusUnauthorized, ProtoMajor: 1, ProtoMinor: 1}
			resp.Write(conn)
			conn.Close()
			return
		}
	}

	var wg sync.WaitGroup

	if req.Method == http.MethodConnect {
		// acknowledge CONNECT
		resp := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1}
		resp.Write(conn)

		stream := handleConnect(conn, req, logger)
		if stream == nil {
			return
		}
		defer stream.Close()
		defer conn.Close()

		wg.Add(1)
		go transfer(stream, conn, &wg, logger.With("phase", "client->proxy"))
		wg.Add(1)
		go transfer(conn, stream, &wg, logger.With("phase", "proxy->client"))
		wg.Wait()

	} else {
		// normal HTTP
		req.Header.Del("Proxy-Authorization")
		if req.URL.Scheme == "http" && !strings.Contains(req.URL.Host, ":") {
			req.URL.Host += ":80"
		}

		stream := handleConnect(conn, req, logger)
		if stream == nil {
			return
		}
		defer stream.Close()
		defer conn.Close()

		// send the request over MASQUE
		err := req.Write(stream)
		if err != nil {
			logger.Error("Failed to write request to MASQUE stream", "err", err)
			return
		}

		wg.Add(1)
		go transfer(stream, conn, &wg, logger.With("phase", "resp->client"))
		wg.Add(1)
		go transfer(conn, stream, &wg, logger.With("phase", "client->proxy"))
		wg.Wait()
	}
}

func runStatusServer() {
	current := "0.0.0.0"
	if ips, err := net.LookupHost(*invisvRelay); err == nil && len(ips) > 0 {
		current = ips[0]
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"currentRelay":"%s"}`, current)))
	})
	log.Fatal(http.ListenAndServe(fmt.Sprintf("localhost:%d", *listenStatusPort), nil))
}

func main() {
	flag.Parse()
	if *token == "" || *invisvRelay == "" {
		flag.Usage()
		os.Exit(1)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	// load cert data if provided
	var certData []byte
	if *certDataFile != "" {
		b, err := os.ReadFile(*certDataFile)
		if err != nil {
			log.Fatalf("Error reading cert file: %v", err)
		}
		certData = b
	}

	// initialize HTTP/3 MASQUE client
	cfg := masqueH3.ClientConfig{
		ProxyAddr: fmt.Sprintf("%s:%d", *invisvRelay, *invisvRelayPort),
		AuthToken: *token,
		CertData:  certData,
		Insecure:  *insecure,
		Logger:    logger,
	}
	c, err := masqueH3.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize MASQUE HTTP3 client: %v", err)
	}
	relayClient = c

	// start status server
	go runStatusServer()

	// listen for proxy clients
	ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *listenPort))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("Accept error", "err", err)
			continue
		}
		go handleReq(conn, logger.With("handler", "handleReq"))
	}
}
