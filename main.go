package main

import (
	"context"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/philband/go-json-panic-repro/pkg/envelope"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	uid := uuid.New()
	dst := filepath.Join("data", uid.String())

	el, err := envelope.NewEnvelopeLogger(dst, envelope.WalModeAppend)
	if err != nil {
		panic(err)
	}

	eg, egCtx := errgroup.WithContext(ctx)
	done := make(chan struct{})

	eg.Go(func() error { return el.RunLogger(egCtx, done) })

	for i := 0; i < 50000; i++ {
		el.Buffer <- envelope.Envelope{
			Type: envelope.LogMessageIvtName,
			Data: envelope.LogMessageIvt{
				Timestamp:   1456465,
				Voltage:     600000,
				Current:     50000,
				Temperature: 544,
			},
		}
	}
	close(done)
	err = eg.Wait()
	if err != nil {
		panic(err)
	}
}
