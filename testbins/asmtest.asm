; nasm -f macho64 challenge.asm -o challenge.o
; ld -macosx_version_min 10.7.0 -lSystem challenge.o -o challenge
; otool -t -v -j ./asmtest

default rel

global start

section .text
start:
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

	; print welcome message
	mov		rsi, msg1
	mov		rdx, msg1.len
	call	puts

	; read name
	;mov		rax, 0x2000003 ; read
	;mov		rdi, 0 ; stdin
	;mov		rsi, buf
	;mov		rdx, 32
	;syscall	

	; print hello
	mov		rsi, msg2
	mov		rdx, msg2.len
	call	puts

	; print hello
	mov		rsi, buf
	mov		rdx, 32
	call	puts	

exit:
	mov		rax, 0x2000001 ; exit
	mov		rdi, 0
	syscall

puts:
	mov		rax, 0x2000004 ; write
	mov		rdi, 1 ; stdout
	syscall
	retn

section .data
buf:
	db		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	db		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
msg1:
	db		"What is your name?", 0x0a
	.len:   equ	$ - msg1
msg2:
	db		"Hello, "
	.len:   equ	$ - msg2


