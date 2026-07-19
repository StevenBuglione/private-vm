package cli

import "time"

const (
	defaultTimeout = 5 * time.Minute
	maximumTimeout = 24 * time.Hour
)

type Options struct {
	ConfigPath     string
	JSON           bool
	NoColor        bool
	NonInteractive bool
	Timeout        time.Duration
	LogLevel       string
	Strict         bool
	Version        bool
}

func defaultOptions() Options {
	return Options{
		Timeout:  defaultTimeout,
		LogLevel: "info",
	}
}
