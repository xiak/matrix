// matrix-terminal-shell is a test-only controlled /bin/sh fixture. It proves
// the real Docker exec TTY stream and resize contract without adding a shell to
// the release workload or allowing an arbitrary host command surface.
package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const acceptedCommand = "printf 'matrix-terminal-ok\\n'; exit\n"

func main() {
	reader := bufio.NewReaderSize(os.Stdin, 4096)
	command, err := reader.ReadString('\n')
	if err != nil || command != acceptedCommand || reader.Buffered() != 0 {
		os.Exit(2)
	}
	size, err := unix.IoctlGetWinsize(int(os.Stdin.Fd()), unix.TIOCGWINSZ)
	if err != nil || size.Row == 0 || size.Col == 0 {
		os.Exit(3)
	}
	_, _ = fmt.Fprintf(os.Stdout, "matrix-terminal-ok %dx%d\n", size.Row, size.Col)
}
