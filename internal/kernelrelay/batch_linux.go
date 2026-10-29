//go:build linux

package kernelrelay

import "syscall"

func truncatedMessage(flags int) bool {
	return flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0
}
