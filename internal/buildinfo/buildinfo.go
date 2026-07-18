package buildinfo

import "runtime"

// These variables are overridden with -ldflags in release builds.
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
	Dirty   = "true"
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	Dirty     string `json:"dirty"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func Current() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		Dirty:     Dirty,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}
