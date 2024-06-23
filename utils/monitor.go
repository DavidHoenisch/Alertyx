package utils

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/DavidHoenisch/Alertyx/analysis"
	"github.com/DavidHoenisch/Alertyx/common"
	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/output"
)

func AlertyxMonitor() {
	output.Info("Welcome to alertyx :)")

	// Quit when program receives CTRL-C.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	// Events context (contains output/error channels and *sync.WaitGroup)
	evCtx := events.NewContext()
	evChan := make(chan events.Event)

	// List of implemented sources
	sourceList := []func(chan events.Event, events.Ctx){
		events.ExecBPF,
		events.ListenBPF,
		events.OpenBPF,
		events.ReadlineBPF,
	}

	// Load each eBPF module
	output.Info("Loading eBPF modules...")
	evCtx.LoadWg.Add(len(sourceList))
	for _, sourceFunc := range sourceList {
		go sourceFunc(evChan, evCtx)
	}

	evLoaded := make(chan bool)
	go func() {
		evCtx.LoadWg.Wait()
		evLoaded <- true
	}()

	// Handle output from BPF modules
	go func() {
		output.Info("Beginning monitoring loop...")
		for {
			var detections []*analysis.Detection
			var err error

			select {

			case module := <-evCtx.Load:
				output.Info("Loaded module:", module)
			case <-evLoaded:
				output.Info("All modules loaded!")
			case err := <-evCtx.Error:
				output.Negative("Error:", err)

			case ev := <-evChan:
				events.Log(ev)
				switch ev.(type) {
				case *events.Exec:
					detections, err = analysis.Exec(ev.(*events.Exec))
				case *events.Listen:
					detections, err = analysis.Listen(ev.(*events.Listen))
				case *events.Open:
					detections, err = analysis.Open(ev.(*events.Open))
				case *events.Readline:
					detections, err = analysis.Readline(ev.(*events.Readline))
				}
				if typeHeader := events.TypeHeader(ev); !output.IsIgnored(common.IgnoreList, typeHeader) {
					output.Event(typeHeader, fmt.Sprintf("%s {ret: %d} (uid: %d) [pid: %d]", ev.Print(), ev.FetchRetVal(), ev.FetchUid(), ev.FetchPid()))
				}
			}

			// Handle detection results
			if err != nil {
				output.Err(err)
				continue
			}
			for _, det := range detections {
				analysis.Log(*det)
				if det.Dupe.Tech != nil {
					if common.Duplicates {
						output.Leveled(det.Level, "DUPLICATE!", det.Print())
					}
				} else {
					output.Leveled(det.Level, det.Print())
					output.Tabber(1)
					output.Negative(det.Brief())
					for i := len(det.Artifacts) - 1; i >= 0; i-- {
						art := det.Artifacts[i]
						output.EventLog(art.Time, events.TypeHeader(art.Ev), art.Ev.Print())
					}
				}

				if common.Active {
					// Clean most recent artifact
					if len(det.Artifacts) > 0 {
						output.Positive("Cleaning:", det.Tech.Name())
						if err := det.Tech.Clean(det.Artifacts[0].Ev); err != nil {
							output.Negative("Cleaning failed:", err.Error())
						}
					}
					if common.Mitigate {
						output.Positive("Mitigating", det.Tech)
						det.Tech.Mitigate()
					}
				}
				output.Tabber(0)
			}
		}
	}()

	<-sig
	output.Info("Waiting for monitoring routines to quit...")
	evCtx.Quit <- true
}
