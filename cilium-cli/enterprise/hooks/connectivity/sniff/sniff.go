package sniff

import "time"

const (
	// Max remote sniffer runtime to prevent lingering processes in the pod.
	// By default, tests should be using the default one defined in the OSS
	// cilium-cli/connectivity/sniff.SniffKillTimeout.
	// However, some enterprise CLI test such as mixed routing requires that
	// tcpdump runs for the whole duration of all running tests.
	// NOTE: too low may kill tcpdump while test is running.
	SniffKillTimeout = 3 * time.Hour
)
