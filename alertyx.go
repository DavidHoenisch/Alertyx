package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/DavidHoenisch/Alertyx/analysis"
	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/output"
	"github.com/DavidHoenisch/Alertyx/techs"

	"github.com/spf13/cobra"
)

var (
	active      bool
	mitigate    bool
	duplicates  bool
	interactive bool
	ignoreList  []string
)

const (
	version = "0.0.5"
)

// main is the entry point of the program. It defines the commands and flags for the alertyx CLI tool and executes the selected command.
func main() {
	cmdMonitor := &cobra.Command{
		Use:     "monitor",
		Aliases: []string{"m", "mon", "eyes"},
		Short:   "actively monitor for malicious action",
		Run: func(cmd *cobra.Command, args []string) {
			alertyxMonitor()
		},
	}

	cmdMonitor.Flags().BoolVarP(&mitigate, "mitigate", "m", false, "attempt to mitigate detected techniques")
	cmdMonitor.Flags().BoolVarP(&duplicates, "duplicates", "d", false, "show duplicate detections")
	cmdMonitor.Flags().StringSliceVarP(&ignoreList, "ignore", "i", []string{}, "don't show certain event types in verbose mode (ex. -i open)")

	cmdHunt := &cobra.Command{
		Use:     "hunt",
		Aliases: []string{"h", "uwu"},
		Short:   "hunt for existing malicious activity",
		Run: func(cmd *cobra.Command, args []string) {
			alertyxHunt()
		},
	}

	cmdHunt.Flags().BoolVarP(&mitigate, "mitigate", "m", false, "attempt to mitigate detected techniques")

	cmdMitigate := &cobra.Command{
		Use:     "mitigate",
		Aliases: []string{"mit", "cybpat"},
		Short:   "mitigate all known vulnerabilities",
		Run: func(cmd *cobra.Command, args []string) {
			alertyxMitigate()
		},
	}

	cmdVersion := &cobra.Command{
		Use:   "version",
		Short: "print alertyx version",
		Run: func(cmd *cobra.Command, args []string) {
			output.Notice("alertyx version", version)
		},
	}

	rootCmd := &cobra.Command{
		Use: "alertyx",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			output.Init()
		},
	}

	rootCmd.PersistentFlags().BoolVarP(&active, "active", "a", false, "counter detected malicious activity (dangerous, may clobber)")
	rootCmd.PersistentFlags().BoolVarP(&output.Verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&output.Syslog, "syslog", "s", false, "output to syslog")
	rootCmd.AddCommand(cmdMonitor, cmdHunt, cmdMitigate, cmdVersion)
	rootCmd.Execute()
}

// alertyxMonitor is a function that sets up and starts a monitoring loop. It listens for events and handles their output and detection results.
// The function prints a welcome message and starts monitoring when called.
// When the program receives a CTRL-C signal, it quits the monitoring routines.
// It creates an events context that contains output and error channels, as well as a WaitGroup.
// It also creates a channel for receiving events.
// A list of implemented sources is defined, which includes functions that handle different types of events.
// The function loads each eBPF module concurrently and waits for all modules to be loaded.
// It then handles the output from the BPF modules, logging events and calling the appropriate analysis function based on the event type.
// The function also handles detection results, printing them and performing any necessary actions such as cleaning or mitigation.
// The monitoring loop runs until the program receives a signal.
// The function sends a quit signal to the events context to cleanly exit all monitoring routines.
func alertyxMonitor() {
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
				if typeHeader := events.TypeHeader(ev); !output.IsIgnored(ignoreList, typeHeader) {
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
					if duplicates {
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

				if active {
					// Clean most recent artifact
					if len(det.Artifacts) > 0 {
						output.Positive("Cleaning:", det.Tech.Name())
						if err := det.Tech.Clean(det.Artifacts[0].Ev); err != nil {
							output.Negative("Cleaning failed:", err.Error())
						}
					}
					if mitigate {
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

// alertyxHunt is a function that performs hunting for existing malicious activity.
// It retrieves a list of all available techniques using the `techs.All` function and iterates over each technique.
// For each technique, it prints a hunting message and calls the `Hunt` method to check for evidence of exploitation.
// If an error occurs during the hunting process, it prints an error message.
// If the hunting result indicates that a technique has been found, it prints a positive message with the name of the technique and the event details. It also performs additional actions
func alertyxHunt() {
	ts := techs.All()
	for _, t := range ts {
		output.Info("Hunting:", t.Name())
		if res, err := t.Hunt(); err != nil {
			output.Negative("Error in hunting:", t.Name()+":", err.Error())
		} else if res.Found {
			output.Positive("Found:", t.Name(), res.Ev.Print())
			if active {
				t.Clean(res.Ev)
				if mitigate {
					t.Mitigate()
				}
			}
		}
	}
}

// alertyxMitigate is a function that checks for mitigation techniques for each tech in the techs.All list. It iterates through the list and checks for mitigation for each technique
func alertyxMitigate() {
	ts := techs.All()
	for _, t := range ts {
		output.Info("Checking:", t.Name())
		if res, err := t.Check(); err != nil {
			output.Negative("Error in checking for mitigation:", t.Name()+":", err.Error())
		} else if res.Found {
			if !active {
				output.Positive("Mitigation possible:", t.Name())
				if res.Ev != nil {
					output.Tabber(1)
					output.Negative(res.Ev.Print)
					output.Tabber(0)
				}
			} else {
				output.Info("Mitigating:", t.Name())
				if err := t.Mitigate(); err != nil {
					output.Negative("Error in mitigating:", t.Name()+":", err.Error())
				} else {
					output.Positive("Mitigated:", t.Name())
				}
			}
		}
	}
}
