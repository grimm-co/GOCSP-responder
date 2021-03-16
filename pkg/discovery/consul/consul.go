package consul

import (
	"strconv"

	"math/rand"

	"github.com/lamassuiot/GOCSP-responder/pkg/discovery"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	consulsd "github.com/go-kit/kit/sd/consul"
	"github.com/hashicorp/consul/api"
)

type ServiceDiscovery struct {
	client    consulsd.Client
	logger    log.Logger
	registrar *consulsd.Registrar
}

func NewServiceDiscovery(consulProtocol string, consulHost string, consulPort string, CA string, logger log.Logger) (discovery.Service, error) {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = consulProtocol + "://" + consulHost + ":" + consulPort
	tlsConf := &api.TLSConfig{CAFile: CA}
	consulConfig.TLSConfig = *tlsConf
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Consul API Client")
		return nil, err
	}
	client := consulsd.NewClient(consulClient)
	return &ServiceDiscovery{client: client, logger: logger}, nil
}

func (sd *ServiceDiscovery) Register(advProtocol string, advHost string, advPort string) error {
	check := api.AgentServiceCheck{
		HTTP:          advProtocol + "://" + advHost + ":" + advPort + "/health",
		Interval:      "10s",
		Timeout:       "1s",
		TLSSkipVerify: true,
		Notes:         "Basic health checks",
	}

	port, _ := strconv.Atoi(advPort)
	num := rand.Intn(100)
	asr := api.AgentServiceRegistration{
		ID:      "ocspresponder" + strconv.Itoa(num),
		Name:    "ocspresponder",
		Address: advHost,
		Port:    port,
		Tags:    []string{"ocsp", "responder"},
		Check:   &check,
	}
	sd.registrar = consulsd.NewRegistrar(sd.client, &asr, sd.logger)
	sd.registrar.Register()
	return nil
}

func (sd *ServiceDiscovery) Deregister() error {
	sd.registrar.Deregister()
	return nil
}
