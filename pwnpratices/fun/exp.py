from pwn import *

r = remote("node3.buuoj.cn", 27490)
for i in range(0, 32):
    r.recvuntil("take ")
    choice = r.recv(1)
    r.recvline()
    if i % 3 == 0:
        if choice == 'r':
            r.sendline("p")
        elif choice == 'p':
            r.sendline("s")
        elif choice == 's':
            r.sendline("r")
    elif i % 3 == 1:
        if choice == 'r':
            r.sendline("s")
        elif choice == 'p':
            r.sendline("r")
        elif choice == 's':
            r.sendline("p")
    else:
        if choice == 'r':
            r.sendline("r")
        elif choice == 'p':
            r.sendline("p")
        elif choice == 's':
            r.sendline("s")
r.interactive()
