package utils

import (
	"github.com/DavidHoenisch/Alertyx/common"
	"github.com/DavidHoenisch/Alertyx/output"
	"github.com/DavidHoenisch/Alertyx/techs"
)

func AlertyxHunt() {
	ts := techs.All()
	for _, t := range ts {
		output.Info("Hunting:", t.Name())
		if res, err := t.Hunt(); err != nil {
			output.Negative("Error in hunting:", t.Name()+":", err.Error())
		} else if res.Found {
			output.Positive("Found:", t.Name(), res.Ev.Print())
			if common.Active {
				t.Clean(res.Ev)
				if common.Mitigate {
					t.Mitigate()
				}
			}
		}
	}
}
