package utils

import (
	"github.com/DavidHoenisch/Alertyx/common"
	"github.com/DavidHoenisch/Alertyx/output"
	"github.com/DavidHoenisch/Alertyx/techs"
)

func AlertyxMitigate() {
	ts := techs.All()
	for _, t := range ts {
		output.Info("Checking:", t.Name())
		if res, err := t.Check(); err != nil {
			output.Negative("Error in checking for mitigation:", t.Name()+":", err.Error())
		} else if res.Found {
			if !common.Active {
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
