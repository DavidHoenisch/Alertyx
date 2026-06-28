package techs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/DavidHoenisch/Alertyx/events"
)

var moduleLoaderBins = []string{
	"insmod",
	"modprobe",
}

var (
	t1547EtcModulesPath    = "/etc/modules"
	t1547ModulesLoadDir    = "/etc/modules-load.d"
	t1547LibModulesDir     = "/lib/modules"
	t1547KernelReleasePath = "/proc/sys/kernel/osrelease"
)

var t1547SkipModuleWalkDirs = map[string]bool{
	"build":  true,
	"source": true,
	"vdso":   true,
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

func (t T1547) Hunt() (Finding, error) {
	release, err := t1547KernelRelease()
	if err != nil {
		return Finding{}, err
	}

	registered, err := t1547LoadModulesDep(release)
	if err != nil {
		return Finding{}, err
	}

	suspicious, err := t1547FindUnregisteredModules(release, registered)
	if err != nil {
		return Finding{}, err
	}
	if len(suspicious) == 0 {
		return Finding{}, nil
	}

	autoload, err := t1547ReadAutoloadModules()
	if err != nil {
		return Finding{}, err
	}
	if path, ok := t1547AutoloadTargetsUnregistered(autoload, suspicious); ok {
		return t1547HuntFinding(path, LevelCrit), nil
	}
	return t1547HuntFinding(suspicious[0], LevelErr), nil
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

func t1547KernelRelease() (string, error) {
	data, err := os.ReadFile(t1547KernelReleasePath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func t1547LoadModulesDep(release string) (map[string]struct{}, error) {
	depPath := filepath.Join(t1547LibModulesDir, release, "modules.dep")
	data, err := os.ReadFile(depPath)
	if err != nil {
		return nil, err
	}
	registered := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ko, _, _ := strings.Cut(line, ":")
		ko = strings.TrimSpace(ko)
		if ko != "" {
			registered[ko] = struct{}{}
		}
	}
	return registered, nil
}

func t1547FindUnregisteredModules(release string, registered map[string]struct{}) ([]string, error) {
	root := filepath.Join(t1547LibModulesDir, release)
	var suspicious []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && t1547SkipModuleWalkDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".ko") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if _, ok := registered[rel]; !ok {
			suspicious = append(suspicious, path)
		}
		return nil
	})
	return suspicious, err
}

func t1547ReadAutoloadModules() ([]string, error) {
	var modules []string
	modules = append(modules, t1547ParseModuleListFile(t1547EtcModulesPath)...)

	entries, err := os.ReadDir(t1547ModulesLoadDir)
	if err != nil {
		if os.IsNotExist(err) {
			return modules, nil
		}
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		path := filepath.Join(t1547ModulesLoadDir, entry.Name())
		modules = append(modules, t1547ParseModuleListFile(path)...)
	}
	return modules, nil
}

func t1547ParseModuleListFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var modules []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			modules = append(modules, fields[0])
		}
	}
	return modules
}

func t1547AutoloadTargetsUnregistered(autoload, suspicious []string) (string, bool) {
	byName := make(map[string]string, len(suspicious))
	for _, path := range suspicious {
		name := strings.TrimSuffix(filepath.Base(path), ".ko")
		byName[name] = path
	}
	for _, mod := range autoload {
		if path, ok := byName[mod]; ok {
			return path, true
		}
	}
	return "", false
}

func t1547HuntFinding(path string, level int) Finding {
	ev := &events.Open{Flags: int32(os.O_RDONLY)}
	t1547CopyEventString(ev.Filename[:], path)
	t1547CopyEventString(ev.Pwd[:], filepath.Dir(path))
	return Finding{Ev: ev, Found: true, Level: level}
}

func t1547CopyEventString(dst []byte, s string) {
	copy(dst, s)
	if len(s) < len(dst) {
		dst[len(s)] = 0
	}
}
