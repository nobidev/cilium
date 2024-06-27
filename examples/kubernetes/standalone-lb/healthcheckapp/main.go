package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
)

func main() {
	c := getConfig()

	server := NewServer(c)

	http.HandleFunc(fmt.Sprintf("GET %s", c.ServicePath), server.serveService)
	http.HandleFunc(fmt.Sprintf("GET %s", c.HealthCheckPath), server.serveHealthCheck)
	http.HandleFunc("POST /control/{type}/{value}", server.serveControlUpdate)

	log.Fatal(http.ListenAndServe(c.ListenAddress, nil))
}

type Server struct {
	c *Config

	healthCheckOk atomic.Bool
	responseOk    atomic.Bool
}

func NewServer(config *Config) *Server {
	s := &Server{
		c: config,
	}

	s.healthCheckOk.Store(config.healthCheckOk)
	s.responseOk.Store(config.responseOk)

	return s
}

func (s *Server) serveService(w http.ResponseWriter, r *http.Request) {
	statusCode := http.StatusOK
	healthStatus := "HEALTHY"

	if !s.responseOk.Load() {
		statusCode = http.StatusInternalServerError
		healthStatus = "FAILURE"
	} else if !s.healthCheckOk.Load() {
		// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/health_checking#active-health-checking-fast-failure
		w.Header().Add("x-envoy-immediate-health-check-fail", "true")
		healthStatus = "UNHEALTHY"
	}

	w.WriteHeader(statusCode)
	fmt.Fprintf(w, "%s - %s: %d - %s (%s) (Remote Addr (T2)): %s)\n", s.c.ServiceName, s.c.InstanceName, statusCode, http.StatusText(statusCode), healthStatus, r.RemoteAddr)
	slog.Info("Service request", "request.path", r.URL.Path, "response.status", statusCode, "remote.addr", r.RemoteAddr)
}

func (s *Server) serveHealthCheck(w http.ResponseWriter, r *http.Request) {
	healthStatus := "HEALTHY"
	statusCode := http.StatusOK

	if !s.healthCheckOk.Load() {
		healthStatus = "UNHEALTHY"
		statusCode = http.StatusInternalServerError
	}

	w.WriteHeader(statusCode)
	fmt.Fprintf(w, "%s\n", healthStatus)
	slog.Info("Health request", "request.path", r.URL.Path, "response.status", statusCode, "response.health", healthStatus, "remote.addr", r.RemoteAddr)
}

func (s *Server) serveControlUpdate(w http.ResponseWriter, r *http.Request) {
	typeParam := r.PathValue("type")
	valueParam := r.PathValue("value")

	if typeParam == "" || valueParam == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "missing type and/or value parameter")
		slog.Error("Type or Value empty", "request.path", r.URL.Path, "type", typeParam, "value", valueParam)
		return
	}

	value, err := getControlBool(valueParam)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid value parameter")
		slog.Error("Invalid value parameter", "request.path", r.URL.Path, "type", typeParam, "value", valueParam, "error", err)
		return
	}

	control, err := s.getControl(typeParam)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid type parameter")
		slog.Error("Invalid type parameter", "request.path", r.URL.Path, "type", typeParam, "value", valueParam, "error", err)
		return
	}

	control.Store(value)
	fmt.Fprintf(w, "%s OK: %t\n", typeParam, value)
	slog.Info("Control request", "request.path", r.URL.Path, "controlType", typeParam, "value", value)
}

func getControlBool(value string) (bool, error) {
	switch value {
	case "ok":
		return true, nil
	case "fail":
		return false, nil
	default:
		return false, fmt.Errorf("invalid control value [ok|fail] %s", value)
	}
}

func (s *Server) getControl(name string) (*atomic.Bool, error) {
	switch name {
	case "healthcheck":
		return &s.healthCheckOk, nil
	case "response":
		return &s.responseOk, nil
	default:
		return nil, fmt.Errorf("no control for %s", name)
	}
}

func getConfig() *Config {
	serviceName := os.Getenv("SERVICE_NAME")
	if len(serviceName) == 0 {
		serviceName = "unknown"
	}

	instanceName := os.Getenv("INSTANCE_NAME")
	if len(instanceName) == 0 {
		instanceName = "unknown"
	}

	listenAddress := os.Getenv("LISTEN_ADDRESS")
	if len(listenAddress) == 0 {
		listenAddress = ":8080"
	}

	servicePath := os.Getenv("SERVICE_PATH")
	if len(servicePath) == 0 {
		servicePath = "/"
	}

	healthCheckPath := os.Getenv("HELTH_CHECK_PATH")
	if len(healthCheckPath) == 0 {
		healthCheckPath = "/health"
	}

	healthCheckOkString := os.Getenv("HEALTHCHECK_OK")
	if len(healthCheckOkString) == 0 {
		healthCheckOkString = "true"
	}

	healthCheckOk, err := strconv.ParseBool(healthCheckOkString)
	if err != nil {
		panic(err)
	}

	responseOkString := os.Getenv("RESPONSE_OK")
	if len(responseOkString) == 0 {
		responseOkString = "true"
	}

	responseOk, err := strconv.ParseBool(responseOkString)
	if err != nil {
		panic(err)
	}

	return &Config{
		ServiceName:     serviceName,
		InstanceName:    instanceName,
		ListenAddress:   listenAddress,
		ServicePath:     servicePath,
		HealthCheckPath: healthCheckPath,
		healthCheckOk:   healthCheckOk,
		responseOk:      responseOk,
	}
}

type Config struct {
	ServiceName     string
	InstanceName    string
	ListenAddress   string
	ServicePath     string
	HealthCheckPath string
	healthCheckOk   bool
	responseOk      bool
}
