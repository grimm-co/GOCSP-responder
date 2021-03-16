package responder

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	GetEndpoint    endpoint.Endpoint
	PostEndpoint   endpoint.Endpoint
	HealthEndpoint endpoint.Endpoint
}

func MakeServerEndpoints(s Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var getEndpoint endpoint.Endpoint
	{
		getEndpoint = MakeOCSPEndpoint(s)
		getEndpoint = opentracing.TraceServer(otTracer, "GetOCSPOperation")(getEndpoint)
	}
	var postEndpoint endpoint.Endpoint
	{
		postEndpoint = MakeOCSPEndpoint(s)
		postEndpoint = opentracing.TraceServer(otTracer, "PostOCSPOperation")(postEndpoint)
	}
	return Endpoints{
		GetEndpoint:    getEndpoint,
		PostEndpoint:   postEndpoint,
		HealthEndpoint: healthEndpoint,
	}
}

func MakeOCSPEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(ocspRequest)
		resp, err := s.Verify(ctx, req.Msg)
		return ocspResponse{Resp: resp, Err: err}, nil
	}
}

func MakeHealthEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return healthResponse{Healthy: healthy}, nil
	}
}

type healthRequest struct{}

type healthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

type ocspRequest struct {
	Msg []byte
}

type ocspResponse struct {
	Resp []byte
	Err  error
}

func (r ocspResponse) error() error { return r.Err }
