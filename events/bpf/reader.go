package bpf

import (
	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/iovisor/gobpf/bcc"
)

func readEvents(event events.Event, evChan chan events.Event, ctx events.Ctx, m *bcc.Module, eventType string) {
	table := bcc.NewTable(m.TableId("events"), m)
	channel := make(chan []byte, 1000)

	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to decode received data", err)
		return
	}

	go func() {
		processor := events.NewEventProcessor()
		ctx.Load <- eventType
		ctx.LoadWg.Done()
		for {
			data := <-channel
			decoded, err := event.Write(data)
			if err != nil {
				ctx.Error <- events.FormatError(eventType, "failed to decode received data", err)
				continue
			}
			if ready, ok := processor.Process(decoded); ok {
				evChan <- ready
			}
		}
	}()

	perfMap.Start()
	<-ctx.Quit
	perfMap.Stop()
}
