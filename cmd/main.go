// Copyright 2016 SMFS Inc DBA GRIMM. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/lamassuiot/GOCSP-responder/pkg/depot/relational"
	"github.com/lamassuiot/GOCSP-responder/pkg/discovery/consul"
	"github.com/lamassuiot/GOCSP-responder/pkg/responder"
	cafile "github.com/lamassuiot/GOCSP-responder/pkg/secrets/ca/file"
	"github.com/lamassuiot/GOCSP-responder/pkg/secrets/responder/file"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	jaegercfg "github.com/uber/jaeger-client-go/config"

	_ "github.com/lib/pq"
)

func main() {
	var (
		flFileCA         = flag.String("fileca", envString("RESPONDER_FILE_CA", ""), "File CA")
		flResponderKey   = flag.String("key", envString("RESPONDER_KEY", ""), "responder key")
		flResponderCert  = flag.String("cert", envString("RESPONDER_CERT", ""), "responder certificate")
		flDepotDBName    = flag.String("dbname", envString("RESPONDER_DB_NAME", "ca_store"), "DB name")
		flDepotDBUser    = flag.String("dbuser", envString("RESPONDER_DB_USER", ""), "DB username")
		flDepotPassword  = flag.String("dbpassword", envString("RESPONDER_DB_PASSWORD", ""), "DB password")
		flDepotHost      = flag.String("dbhost", envString("RESPONDER_DB_HOST", ""), "DB host")
		flDepotPort      = flag.String("dbport", envString("RESPONDER_DB_PORT", ""), "DB port")
		flConsulProtocol = flag.String("consulprotocol", envString("RESPONDER_CONSUL_PROTOCOL", ""), "Consul protocol")
		flConsulHost     = flag.String("consulhost", envString("RESPONDER_CONSUL_HOST", ""), "Consul host")
		flConsulPort     = flag.String("consulport", envString("RESPONDER_CONSUL_PORT", ""), "Consul port")
		flConsulCA       = flag.String("consulca", envString("RESPONDER_CONSUL_CA", ""), "Consul CA path")
		flAddress        = flag.String("bind", envString("RESPONDER_ADDRESS", ""), "bind address")
		flPort           = flag.String("port", envString("RESPONDER_PORT", ""), "listening port")
		flSsl            = flag.Bool("ssl", envBool("RESPONDER_SSL"), "use SSL, this is not widely supported and not recommended")
		flStrict         = flag.Bool("strict", envBool("RESPONDER_STRICT"), "require content type HTTP header")
	)
	flag.Parse()

	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	caSecrets := cafile.NewFile(*flFileCA, logger)
	respSecrets := file.NewFile(*flResponderKey, *flResponderCert, logger)

	dataSourceName := "dbname=" + *flDepotDBName + " user=" + *flDepotDBUser + " password=" + *flDepotPassword + " host=" + *flDepotHost + " port=" + *flDepotPort + " sslmode=disable"
	depot, err := relational.NewDB("postgres", dataSourceName, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with signed certificates database")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Connection established with signed certificates database")
	jcfg, err := jaegercfg.FromEnv()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not load Jaeger configuration values fron environment")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Jaeger configuration values loaded")
	tracer, closer, err := jcfg.NewTracer()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}
	defer closer.Close()
	level.Info(logger).Log("msg", "Jaeger tracer started")
	fieldKeys := []string{"method", "error"}

	var resp responder.Service
	{
		resp, err = responder.NewService(caSecrets, respSecrets, depot)
		if err != nil {
			logger.Log("err", err)
			os.Exit(1)
		}
		resp = responder.LoggingMiddleware(logger)(resp)
		resp = responder.NewInstrumentingMiddleware(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "ocsp_responder",
				Subsystem: "responder",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "ocsp_responder",
				Subsystem: "responder",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
		)(resp)
	}

	h := responder.MakeHTTPHandler(resp, log.With(logger, "component", "HTTP"), *flStrict, tracer)
	http.Handle("/metrics", promhttp.Handler())

	consulsd, err := consul.NewServiceDiscovery(*flConsulProtocol, *flConsulHost, *flConsulPort, *flConsulCA, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with Consul Service Discovery")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Connection established with Consul Service Discovery")

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	if *flSsl {
		go func() {
			level.Info(logger).Log("transport", "HTTPS", "address", *flAddress+":"+*flPort, "msg", "listening")
			consulsd.Register("https", "ocsp", *flPort)
			errs <- http.ListenAndServeTLS(*flAddress+":"+*flPort, *flResponderCert, *flResponderKey, nil)
		}()
	} else {
		go func() {
			level.Info(logger).Log("transport", "HTTP", "address", *flAddress+":"+*flPort, "msg", "listening")
			consulsd.Register("http", "ocsp", *flPort)
			errs <- http.ListenAndServe(*flAddress+":"+*flPort, h)
		}()
	}
	level.Info(logger).Log("exit", <-errs)
}

func envString(key, def string) string {
	if env := os.Getenv(key); env != "" {
		return env
	}
	return def
}

func envBool(key string) bool {
	if env := os.Getenv(key); env == "true" {
		return true
	}
	return false
}

func envInt(key string, def int) int {
	if env := os.Getenv(key); env != "" {
		env, _ := strconv.Atoi(env)
		return env
	}
	return def
}