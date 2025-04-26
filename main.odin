package main

import "core:fmt"
import "core:io"
import "core:os"
import "core:strconv"
import "core:strings"
import sys "core:sys/linux"

Debugger :: struct {
	program:     string,
	pid:         sys.Pid,
	breakpoints: map[uintptr]Breakpoint,
}

debugger_init :: proc(dbg: ^Debugger) {
	dbg.breakpoints = make(map[uintptr]Breakpoint)
}

debugger_set_breakpoint_at_address :: proc(dbg: ^Debugger, addr: uintptr) {
	fmt.printfln("Set breakpoint address at 0x%X", addr)
	bp := Breakpoint {
		pid  = dbg.pid,
		addr = addr,
	}
	breakpoint_enable(&bp)
	dbg.breakpoints[addr] = bp
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

		execl_err := sys.execve(cprogram, nil, nil)
		if execl_err != nil {
			fmt.eprintln("Execl error:", execl_err)
			os.exit(1)
		}
		fmt.println("Success")
	} else if pid >= 1 {
		fmt.println("Started debugging process", pid)
		dbg := Debugger {
			program = program,
			pid     = pid,
		}
		debugger_init(&dbg)

		wait_status: u32
		pid, err_no = sys.waitpid(pid, &wait_status, nil, nil)

		stdin_stream := os.stream_from_handle(os.stdin)
		for {
			fmt.print("my_debugger> ")
			line, read_err := read_line(stdin_stream)
			defer if read_err == nil {
				delete(line)
			}
			if read_err != nil {
				fmt.eprintln("Error when reading stdin:", read_err)
				continue
			}
			handle_command(&dbg, line)
		}
	}
}

handle_command :: proc(dbg: ^Debugger, line: string) {
	args := strings.split(line, " ")
	if len(args) == 0 {
		return
	}
	command := args[0]

	switch command {
	case "continue":
		continue_execution(dbg)
	case "break":
		if len(args) < 2 {
			fmt.println("Not enough arguments")
			return
		}
		potential_address := args[1]
		potential_address = potential_address[2:]
		address, ok := strconv.parse_uint(potential_address, 16)
		if !ok {
			fmt.println("Incorrect address")
			return
		}
		debugger_set_breakpoint_at_address(dbg, cast(uintptr)address)
	case:
		fmt.println("Unknown command")
		return
	}
}

continue_execution :: proc(dbg: ^Debugger) {
	sys.ptrace_cont(.CONT, dbg.pid, nil)

	wait_status: u32
	sys.waitpid(dbg.pid, &wait_status, nil, nil)
}

read_line :: proc(s: io.Stream) -> (string, io.Error) {
	builder := strings.builder_make()
	for {
		b, read_err := io.read_byte(s)
		if read_err != nil {
			return "", read_err
		}
		if b == '\n' {
			return strings.to_string(builder), nil
		}
		strings.write_byte(&builder, b)
	}
}

Breakpoint :: struct {
	pid:        sys.Pid,
	addr:       uintptr,
	enabled:    bool,
	saved_data: u8,
}

breakpoint_enable :: proc(bp: ^Breakpoint) {
	data, peek_err := sys.ptrace_peek(.PEEKDATA, bp.pid, bp.addr)
	bp.saved_data = cast(u8)(data & 0xff)
	int3: uint = 0xcc
	data_with_int3 := (data & ~cast(uint)0xff) | int3
	sys.ptrace_poke(.POKEDATA, bp.pid, bp.addr, data_with_int3)

	bp.enabled = true
}

breakpoint_disable :: proc(bp: ^Breakpoint) {
	data, peek_err := sys.ptrace_peek(.PEEKDATA, bp.pid, bp.addr)
	restored_data := (data & ~cast(uint)0xff) | cast(uint)bp.saved_data
	poke_err := sys.ptrace_poke(.POKEDATA, bp.pid, bp.addr, restored_data)

	bp.enabled = false
}
