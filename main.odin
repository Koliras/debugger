#+feature dynamic-literals
package main

import "core:fmt"
import "core:io"
import "core:os"
import "core:strconv"
import "core:strings"
import sys "core:sys/linux"

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

debugger_dump_registers :: proc(dbg: ^Debugger) {
	regs: sys.User_Regs
	ptrace_err := sys.ptrace_getregs(.GETREGS, dbg.pid, &regs)
	regs_arr := transmute([27]uint)regs
	fmt.print(
		"r15:",
		regs.r15,
		"\n",
		"r14:",
		regs.r14,
		"\n",
		"r13:",
		regs.r13,
		"\n",
		"r12:",
		regs.r12,
		"\n",
		"rbp:",
		regs.rbp,
		"\n",
		"rbx:",
		regs.rbx,
		"\n",
		"r11:",
		regs.r11,
		"\n",
		"r10:",
		regs.r10,
		"\n",
		"r9:",
		regs.r9,
		"\n",
		"r8:",
		regs.r8,
		"\n",
		"rax:",
		regs.rax,
		"\n",
		"rcx:",
		regs.rcx,
		"\n",
		"rdx:",
		regs.rdx,
		"\n",
		"rsi:",
		regs.rsi,
		"\n",
		"rdi:",
		regs.rdi,
		"\n",
		"orig_rax:",
		regs.orig_rax,
		"\n",
		"rip:",
		regs.rip,
		"\n",
		"cs:",
		regs.cs,
		"\n",
		"eflags:",
		regs.eflags,
		"\n",
		"rsp:",
		regs.rsp,
		"\n",
		"ss:",
		regs.ss,
		"\n",
		"fs_base:",
		regs.fs_base,
		"\n",
		"gs_base:",
		regs.gs_base,
		"\n",
		"ds:",
		regs.ds,
		"\n",
		"es:",
		regs.es,
		"\n",
		"fs:",
		regs.fs,
		"\n",
		"gs:",
		regs.gs,
		"\n",
	)
}

debugger_get_pc :: #force_inline proc(dbg: ^Debugger) -> uint {
	return register_get_value(dbg.pid, .rip)
}

debugger_set_pc :: #force_inline proc(dbg: ^Debugger, pc: uint) {
	register_set_value(dbg.pid, .rip, pc)
}

debugger_step_over_breakpoint :: proc(dbg: ^Debugger) {
	possible_breakpoint_location := debugger_get_pc(dbg) - 1
	breakpoint, has_breakpoint := &dbg.breakpoints[cast(uintptr)possible_breakpoint_location]
	if !has_breakpoint do return
	if !breakpoint.enabled do return

	debugger_set_pc(dbg, possible_breakpoint_location)
	breakpoint_disable(breakpoint)
	sys.ptrace_singlestep(.SINGLESTEP, dbg.pid, nil)
	debugger_wait_for_signal(dbg)
	breakpoint_enable(breakpoint)
}

debugger_wait_for_signal :: proc(dbg: ^Debugger) {
	wait_status: u32
	sys.waitpid(dbg.pid, &wait_status, nil, nil)
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
	case "register":
		if len(args) < 2 {
			fmt.println("Not enough arguments")
			return
		}
		switch args[1] {
		case "dump":
			debugger_dump_registers(dbg)
		case "read":
			if len(args) < 3 {
				fmt.println("Not enough arguments")
				return
			}
			reg, valid_register := STRING_TO_REGISTER[args[2]]
			if !valid_register {
				fmt.println("Invalid register name")
				return
			}
			fmt.println(register_get_value(dbg.pid, reg))
		case "write":
			if len(args) < 4 {
				fmt.println("Not enough arguments")
				return
			}
			reg, valid_register := STRING_TO_REGISTER[args[2]]
			if !valid_register {
				fmt.println("Invalid register")
				return
			}
			val, correct_val := strconv.parse_uint(args[2])
			if !correct_val {
				fmt.println("Incorrect value to set to register")
				return
			}
			register_set_value(dbg.pid, reg, val)
		}
	case:
		fmt.println("Unknown command")
		return
	}
}

continue_execution :: proc(dbg: ^Debugger) {
	debugger_step_over_breakpoint(dbg)
	sys.ptrace_cont(.CONT, dbg.pid, nil)
	debugger_wait_for_signal(dbg)
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

Register_Type :: enum {
	r15,
	r14,
	r13,
	r12,
	rbp,
	rbx,
	r11,
	r10,
	r9,
	r8,
	rax,
	rcx,
	rdx,
	rsi,
	rdi,
	orig_rax,
	rip,
	cs,
	eflags,
	rsp,
	ss,
	fs_base,
	gs_base,
	ds,
	es,
	fs,
	gs,
}

STRING_TO_REGISTER := map[string]Register_Type {
	"r15"      = .r15,
	"r14"      = .r14,
	"r13"      = .r13,
	"r12"      = .r12,
	"rbp"      = .rbp,
	"rbx"      = .rbx,
	"r11"      = .r11,
	"r10"      = .r10,
	"r9"       = .r9,
	"r8"       = .r8,
	"rax"      = .rax,
	"rcx"      = .rcx,
	"rdx"      = .rdx,
	"rsi"      = .rsi,
	"rdi"      = .rdi,
	"orig_rax" = .orig_rax,
	"rip"      = .rip,
	"cs"       = .cs,
	"eflags"   = .eflags,
	"rsp"      = .rsp,
	"ss"       = .ss,
	"fs_base"  = .fs_base,
	"gs_base"  = .gs_base,
	"ds"       = .ds,
	"es"       = .es,
	"fs"       = .fs,
	"gs"       = .gs,
}

DWARF_TO_REGISTER := map[int]Register_Type {
	15 = .r15,
	14 = .r14,
	13 = .r13,
	12 = .r12,
	6  = .rbp,
	3  = .rbx,
	11 = .r11,
	10 = .r10,
	9  = .r9,
	8  = .r8,
	0  = .rax,
	2  = .rcx,
	1  = .rdx,
	4  = .rsi,
	5  = .rdi,
	-1   = .orig_rax,
	-1   = .rip,
	51 = .cs,
	49 = .eflags,
	7  = .rsp,
	52 = .ss,
	58 = .fs_base,
	59 = .gs_base,
	53 = .ds,
	50 = .es,
	54 = .fs,
	55 = .gs,
}

register_get_value :: proc(pid: sys.Pid, r: Register_Type) -> uint {
	regs: sys.User_Regs
	ptrace_err := sys.ptrace_getregs(.GETREGS, pid, &regs)
	return (transmute(^[27]uint)&regs)[r]
}

register_set_value :: proc(pid: sys.Pid, r: Register_Type, val: uint) {
	regs: sys.User_Regs
	ptrace_err := sys.ptrace_getregs(.GETREGS, pid, &regs)
	(transmute(^[27]uint)&regs)[r] = val

	setreg_err := sys.ptrace_setregs(.SETREGS, pid, &regs)
}

register_get_value_from_dwarf :: proc(pid: sys.Pid, register_num: int) -> (val: uint, ok: bool) {
	reg := DWARF_TO_REGISTER[register_num] or_return
	return register_get_value(pid, reg), true
}
