package analysis

import (
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/DavidHoenisch/Alertyx/correlate"
	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/output"
	"github.com/DavidHoenisch/Alertyx/techs"
)

// ToDetectionEvent converts a detection into structured output for SIEM integration.
func (d *Detection) ToDetectionEvent() output.DetectionEvent {
	evt := output.DetectionEvent{
		Timestamp:   d.Time,
		Technique:   d.Tech.Name(),
		TechniqueID: techs.ID(d.Tech),
		Severity:    output.SeverityFromLevel(d.Level),
		Details:     d.Brief(),
		Artifacts:   artifactStrings(d.Artifacts),
	}

	if len(d.Artifacts) == 0 {
		return evt
	}

	ev := d.Artifacts[0].Ev
	evt.PID = ev.FetchPid()
	evt.PPID = ev.FetchPpid()
	evt.UID = ev.FetchUid()
	evt.PWD = ev.FetchPwd()
	evt.Username = usernameForUID(evt.UID)
	evt.Process = processName(ev, d.Artifacts)

	return evt
}

func artifactStrings(artifacts []events.LogItem) []string {
	out := make([]string, 0, len(artifacts))
	for _, art := range artifacts {
		out = append(out, art.Ev.Print())
	}
	return out
}

func usernameForUID(uid uint32) string {
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return "?"
	}
	return u.Username
}

func processName(ev events.Event, artifacts []events.LogItem) string {
	if execEv, ok := ev.(*events.Exec); ok {
		return filepath.Base(events.CStr(execEv.Comm[:]))
	}
	if bin, err := correlate.Bin(artifacts, ev.FetchPid()); err == nil {
		return filepath.Base(bin)
	}
	return "?"
}
