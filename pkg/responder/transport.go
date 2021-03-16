package responder

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"

	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	stdopentracing "github.com/opentracing/opentracing-go"

	"github.com/gorilla/mux"
)

var (
	ErrUnusportedMethod  = errors.New("method not supported")
	ErrURLParsing        = errors.New("error parsing URL")
	ErrUnusportedContent = errors.New("unsuported content type")
	ErrBase64Decoding    = errors.New("error decoding base64")
	ErrReadingPostBody   = errors.New("error reading POST Body")
)

type errorer interface {
	error() error
}

func MakeHTTPHandler(s Service, logger log.Logger, strict bool, otTracer stdopentracing.Tracer) http.Handler {
	r := mux.NewRouter()
	e := MakeServerEndpoints(s, otTracer)

	options := []httptransport.ServerOption{
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
	}

	r.Methods("GET").Path("/health").Handler(httptransport.NewServer(
		e.HealthEndpoint,
		decodeHealthRequest,
		encodeHealthResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Health", logger)))...,
	))

	r.Methods("GET").Handler(httptransport.NewServer(
		e.GetEndpoint,
		checkStrictRequest(strict),
		encodeOCSPResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetOCSPOperation", logger)))...,
	))

	r.Methods("POST").Handler(httptransport.NewServer(
		e.PostEndpoint,
		checkStrictRequest(strict),
		encodeOCSPResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "PostOCSPOperation", logger)))...,
	))

	return r
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req healthRequest
	return req, nil
}

func checkStrictRequest(strict bool) httptransport.DecodeRequestFunc {
	if strict {
		return decodeOCSPStrictRequest
	}
	return decodeOCSPRequest
}

func message(r *http.Request) ([]byte, error) {
	var requestBody []byte
	switch r.Method {
	case "GET":
		base64Request, err := url.QueryUnescape(r.URL.Path)
		if err != nil {
			return nil, ErrURLParsing
		}
		// url.QueryUnescape not only unescapes %2B escaping, but it additionally
		// turns the resulting '+' into a space, which makes base64 decoding fail.
		// So we go back afterwards and turn ' ' back into '+'. This means we
		// accept some malformed input that includes ' ' or %20, but that's fine.
		base64RequestBytes := []byte(base64Request)
		for i := range base64RequestBytes {
			if base64RequestBytes[i] == ' ' {
				base64RequestBytes[i] = '+'
			}
		}
		// In certain situations a UA may construct a request that has a double
		// slash between the host name and the base64 request body due to naively
		// constructing the request URL. In that case strip the leading slash
		// so that we can still decode the request.
		if len(base64RequestBytes) > 0 && base64RequestBytes[0] == '/' {
			base64RequestBytes = base64RequestBytes[1:]
		}
		requestBody, err = base64.StdEncoding.DecodeString(string(base64RequestBytes))
		if err != nil {
			return nil, ErrBase64Decoding
		}
		return requestBody, nil
	case "POST":
		requestBody, err := ioutil.ReadAll(http.MaxBytesReader(nil, r.Body, 10000))
		if err != nil {
			return nil, ErrReadingPostBody
		}
		return requestBody, nil
	default:
		return nil, ErrUnusportedMethod
	}
}

func decodeOCSPStrictRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		return nil, ErrUnusportedContent
	}
	msg, err := message(r)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	return ocspRequest{Msg: msg}, nil
}

func decodeOCSPRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	msg, err := message(r)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	return ocspRequest{Msg: msg}, nil
}

func encodeOCSPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	resp := response.(ocspResponse)
	w.Write(resp.Resp)
	return nil
}

func encodeHealthResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	http.Error(w, err.Error(), codeFrom(err))
}

func codeFrom(err error) int {
	switch err {
	case ErrUnusportedMethod, ErrURLParsing, ErrUnusportedContent:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
