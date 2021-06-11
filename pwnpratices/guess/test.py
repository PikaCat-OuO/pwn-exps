from pwn import *

i = -200
while True:
    r = remote('10.10.202.172', 4396)
    r.recvline()
    r.recvline()
    r.sendline(str(i))
    s = r.recvline()
    print(i)
    print(s)
    i += 1
    r.close()

