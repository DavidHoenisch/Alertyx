package events

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/perf"
)

// ProcessSample decodes one perf buffer sample and merges it through EventProcessor.
func ProcessSample(processor *EventProcessor, template Event, raw []byte) (Event, bool, error) {
	decoded, err := template.Write(raw)
	if err != nil {
		return nil, false, err
	}
	ready, ok := processor.Process(decoded)
	return ready, ok, nil
}

// ReadEvents reads perf buffer samples, merges fragments, and emits complete events.
func ReadEvents(template Event, evChan chan Event, ctx Ctx, rd *perf.Reader, eventType string) {
	go func() {
		processor := NewEventProcessor()
		ctx.Load <- eventType
		ctx.LoadWg.Done()
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				ctx.Error <- FormatError(eventType, "failed to read perf event", err)
				continue
			}
			if record.LostSamples != 0 {
				ctx.Error <- FormatError(eventType, "perf buffer lost samples",
					fmt.Errorf("%d samples lost", record.LostSamples))
				continue
			}

			ready, ok, err := ProcessSample(processor, template, record.RawSample)
			if err != nil {
				ctx.Error <- FormatError(eventType, "failed to decode received data", err)
				continue
			}
			if ok {
				evChan <- ready
			}
		}
	}()
}
