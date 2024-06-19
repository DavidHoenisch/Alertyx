package techs

import (
	"os"
	"strings"

	"github.com/DavidHoenisch/Alertyx/correlate"
	"github.com/DavidHoenisch/Alertyx/events"
)

type T1098 struct {
	techBase
}

func (t T1098) Name() string {
	return "SSH Authorized Keys Manipulation"
}

func (t T1098) Scan(e events.Event) Finding {
	res := Finding{}
	switch e.(type) {
	case *events.Open:
		ev := e.(*events.Open)
		fileName := events.CStr(ev.Filename[:])
		if strings.Contains(fileName, "authorized_keys") {
			if int(ev.Flags) != os.O_RDONLY {
				if ev.RetVal < 0 {
					res.Found = true
					res.Level = LevelWarn
					return res
				}
				owner, err := correlate.Owner(fileName)
				if err != nil {
					res.Found = true
					res.Level = LevelCrit
					return res
				}
				if owner != ev.Uid {
					res.Found = true
					res.Level = LevelCrit
					return res
				}
			}
		}
	}
	return res
}

func (t T1098) Check() (Finding, error) {
	// os.Stat file
	// Ensure permissions of authorized_keys are 644 (or 600?)
	// ensure perms of id_rsa are 600 and id_rsa.pub 644 or 600
	return Finding{}, nil
}

func (t T1098) Mitigate() error {
	// os.Stat file
	// Ensure permissions of authorized_keys are 644 (or 600?)
	// ensure perms of id_rsa are 600 and id_rsa.pub 644 or 600
	return nil
}
