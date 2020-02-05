; MAC:
;   nasm -f macho64 challenge.asm -o challenge.o
;   ld -macosx_version_min 10.7.0 -lSystem challenge.o -o challenge
;   otool -t -v -j ./asmtest

default rel

%ifdef OS_IS_LINUX
	global _start
	section .text
	_start:
%endif

%ifdef OS_IS_MACOS
	global start
	section .text
	start:
%endif

	nop
	call bounce
	nop
	call bounce
	nop
	call bounce
	nop
	call bounce
	nop
	call bounce
	nop
	call bounce
	nop
	call bounce
	nop
	call bounce

	mov		rsi, msg
	mov		rdx, msg.len
	mov		rdi, 1 ; stdout

%ifdef OS_IS_LINUX
	mov		rax, 1 ; write
	syscall
	mov		rdi, 0 ; arg0: status
	mov		rax, 60 ; __NR_exit
	syscall
%endif

%ifdef OS_IS_MACOS
	mov		rax, 0x2000004 ; write
	syscall
	mov		rax, 0x2000001 ; exit
	mov		rdi, 0
	syscall
%endif

bounce:
	retn

section .data
msg:
	db		"Hello, world!", 0x0a
	.len:   equ	$ - msg

