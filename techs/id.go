package techs

import "reflect"

// ID returns the MITRE or local technique identifier (e.g. "L1002", "T1098").
func ID(t Tech) string {
	return reflect.TypeOf(t).Name()
}
