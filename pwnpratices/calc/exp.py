from pwn import *

context.log_level = "DEBUG"
r = remote("node3.buuoj.cn", 29101)
for i in range(0, 150):
    r.recvuntil(": ")
    str1 = r.recvuntil("=")[0:-2]
    r.recvline()
    r.sendline(str(eval(str1)))
r.interactive()
