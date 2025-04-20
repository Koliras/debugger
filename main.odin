package main

import "core:fmt"
import "core:os"
import "core:strings"
import sys "core:sys/linux"

main :: proc() {
	if len(os.args) < 2 {
		fmt.println("Program name not specified")
		os.exit(1)
	}

	program := os.args[1]
	pid, err_no := sys.fork()

	if pid == 0 {
		fmt.println("child process")
		traceme_err := sys.ptrace_traceme(.TRACEME)
		if traceme_err != nil {
			fmt.println("Trace error:", traceme_err)
			os.exit(1)
		}

		cprogram := strings.clone_to_cstring(program)
		program_arr := [?]cstring{cprogram}
		cprogram_multipointer: [^]cstring = raw_data(program_arr[:])

		execl_err := sys.execve(cprogram, cprogram_multipointer, nil)
		if execl_err != nil {
			fmt.println("Execl error:", execl_err)
			os.exit(1)
		}
		fmt.println("Success")
	} else if pid >= 1 {
		fmt.println("parent process")
	}
}
