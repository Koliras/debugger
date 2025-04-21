package main

import "core:fmt"
import "core:io"
import "core:os"
import "core:strings"
import sys "core:sys/linux"

Debugger :: struct {
	program: string,
	pid:     sys.Pid,
}

main :: proc() {
	if len(os.args) < 2 {
		fmt.eprintln("Program name not specified")
		os.exit(1)
	}

	program := os.args[1]
	pid, err_no := sys.fork()
	if err_no != nil {
		fmt.eprintln("Failed to fork process. Error:", err_no)
		os.exit(1)
	}

	if pid == 0 {
		fmt.println("child process")
		traceme_err := sys.ptrace_traceme(.TRACEME)
		if traceme_err != nil {
			fmt.eprintln("Trace error:", traceme_err)
			os.exit(1)
		}

		cprogram := strings.clone_to_cstring(program)
		program_arr := [?]cstring{cprogram}
		cprogram_multipointer: [^]cstring = raw_data(program_arr[:])

		execl_err := sys.execve(cprogram, cprogram_multipointer, nil)
		if execl_err != nil {
			fmt.eprintln("Execl error:", execl_err)
			os.exit(1)
		}
		fmt.println("Success")
	} else if pid >= 1 {
		fmt.println("Started debugging process", pid)
		dbg := Debugger{program, pid}

		wait_status: u32
		pid, err_no = sys.waitpid(pid, &wait_status, {}, nil)

		stdin_stream := os.stream_from_handle(os.stdin)
		for {
			fmt.print("my_debugger> ")
			line, read_err := read_input(stdin_stream)
			defer if read_err == nil {
				delete(line)
			}
			if read_err != nil {
				fmt.eprintln("Error when reading stdin:", read_err)
				continue
			}
			fmt.println(line)
			handle_command(line)
		}
	}
}

handle_command :: proc(command: string) {
	// TODO
}

read_input :: proc(s: io.Stream) -> (string, io.Error) {
	builder := strings.builder_make()
	for {
		b, read_err := io.read_byte(s)
		if read_err != nil {
			if read_err == .EOF {
				return strings.to_string(builder), nil
			}
			return "", read_err
		}
		strings.write_byte(&builder, b)
	}
}
