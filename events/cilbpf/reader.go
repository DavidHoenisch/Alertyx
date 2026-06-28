package cilbpf

import (
	"errors"
	"fmt"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/cilium/ebpf/perf"
)

func readEvents(event events.Event, evChan chan events.Event, ctx events.Ctx, rd *perf.Reader, eventType string) {
	go func() {
		processor := events.NewEventProcessor()
		ctx.Load <- eventType
		ctx.LoadWg.Done()
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				ctx.Error <- events.FormatError(eventType, "failed to read perf event", err)
				continue
			}
			if record.LostSamples != 0 {
				ctx.Error <- events.FormatError(eventType, "perf buffer lost samples",
					fmt.Errorf("%d samples lost", record.LostSamples))
				continue
			}

			decoded, err := event.Write(record.RawSample)
			if err != nil {
				ctx.Error <- events.FormatError(eventType, "failed to decode received data", err)
				continue
			}
			if ready, ok := processor.Process(decoded); ok {
				evChan <- ready
			}
		}
	}()
}
