//go:build !linux

package kernelrelay

// The executable targets Linux. Elsewhere x/net falls back to single-packet
// IO; reject unexpected receive flags conservatively.
func truncatedMessage(flags int) bool { return flags != 0 }
