package techs

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/DavidHoenisch/Alertyx/events"
)

var moduleLoaderBins = []string{
	"insmod",
	"modprobe",
}

type T1547 struct {
	techBase
}

func (t T1547) Name() string {
	return "Kernel Modules Persistence"
}

func (t T1547) Scan(e events.Event) Finding {
	res := Finding{}
	switch ev := e.(type) {
	case *events.Exec:
		if isModuleLoaderExec(events.CStr(ev.Argv[:])) {
			res.Found = true
			res.Level = LevelWarn
		}
	case *events.Open:
		if int(ev.Flags) == os.O_RDONLY {
			return res
		}
		filename := events.CStr(ev.Filename[:])
		pwd := events.CStr(ev.Pwd[:])
		if modulePersistencePath(filename, pwd) {
			res.Found = true
			res.Level = LevelErr
		}
	}
	return res
}

func isModuleLoaderExec(argv string) bool {
	for _, part := range strings.Fields(argv) {
		base := filepath.Base(part)
		for _, loader := range moduleLoaderBins {
			if base == loader {
				return true
			}
		}
	}
	return false
}

func modulePersistencePath(filename, pwd string) bool {
	if filename == "/etc/modules" || strings.HasPrefix(filename, "/lib/modules/") || strings.HasPrefix(filename, "/etc/modules-load.d/") {
		return true
	}
	if filename == "modules" && (pwd == "/etc" || strings.HasSuffix(pwd, "/etc")) {
		return true
	}
	if pwd == "/etc/modules-load.d" || strings.HasPrefix(pwd, "/etc/modules-load.d/") {
		return true
	}
	if pwd == "/lib/modules" || strings.HasPrefix(pwd, "/lib/modules/") {
		return true
	}
	return false
}
