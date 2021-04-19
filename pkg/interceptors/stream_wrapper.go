package interceptors

import (
	"context"
	"google.golang.org/grpc"
)


// StreamContextWrapper is an interface that allows to set new context to stream
type StreamContextWrapper interface {
	grpc.ServerStream
	SetContext(context.Context)
}

// wrapper for a stream context
type wrapper struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the context from the wrapper
func (w *wrapper) Context() context.Context {
	return w.ctx
}

// SetContext set the wrapper context
func (w *wrapper) SetContext(ctx context.Context) {
	w.ctx = ctx
}

// newStreamContextWrapper returns new newStreamContextWrapper from Stream
func newStreamContextWrapper(inner grpc.ServerStream) StreamContextWrapper {
	ctx := inner.Context()
	return &wrapper{
		inner,
		ctx,
	}
}
