.text
.globl _start
_start:
    # set rbp for backtrace
    movq $0x0, %rbp

	mov (%rsp),%rdi
	lea 8(%rsp),%rsi

	mov (%rsp),%rdi
	lea 8(%rsp),%rsi

    # call user-program function
    call umain
1:  jmp 1b

