package techs

import (
	"fmt"
	"os"

	"github.com/DavidHoenisch/Alertyx/correlate"
	"github.com/DavidHoenisch/Alertyx/events"
)

type L1002 struct {
	techBase
}

func (t L1002) Name() string {
	return "Suspicious /etc/shadow Access"
}

func (t L1002) Scan(e events.Event) Finding {
	res := Finding{}
	permittedBins := []string{
		"/usr/bin/su",
		"/usr/bin/sudo",
	}
	switch e.(type) {
	case *events.Open:
		ev := e.(*events.Open)
		if events.CStr(ev.Filename[:]) == "/etc/shadow" {
			callingBin, err := correlate.Bin(events.GetAll(), e.FetchPid())
			if err != nil {
				fmt.Println("l1002: error in fetching correlate bin:", err)
				return res
			}
			if !correlate.InList(permittedBins, callingBin) {
				res.Found = true
				res.Level = LevelWarn
			}
		}
	}
	return res
}

func (t L1002) Check() (Finding, error) {
	// os.Stat file
	// if not 600 be angry
	return Finding{Found: true}, nil
}

func (t L1002) Mitigate() error {
	err := os.Chmod("/etc/shadow", 644)
	return err
}
