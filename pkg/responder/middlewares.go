package responder

import (
	"time"

	"github.com/go-kit/kit/log"

	"context"
)

type Middleware func(Service) Service

func LoggingMiddleware(logger log.Logger) Middleware {
	return func(next Service) Service {
		return &loggingMiddleware{
			next:   next,
			logger: logger,
		}
	}
}

type loggingMiddleware struct {
	next   Service
	logger log.Logger
}

func (mw loggingMiddleware) Health(ctx context.Context) (healthy bool) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Health",
			"healthy", healthy,
			"took", time.Since(begin),
		)
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMiddleware) Verify(ctx context.Context, msg []byte) (resp []byte, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Verify",
			"took", time.Since(begin),
			"err", err)
	}(time.Now())
	return mw.next.Verify(ctx, msg)
}
