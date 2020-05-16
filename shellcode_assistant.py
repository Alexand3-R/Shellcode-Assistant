#!/bin/python3
import sys
import argparse
import os
import time
import pipes
import threading
from capstone import *
from keystone import *
from subprocess import Popen, PIPE
from colorama import Fore, Style

# COMMAND LINE OPTIONS
def cli_options(args=sys.argv[1:]):
	p = argparse.ArgumentParser(description="== Tool to assist a user in modifiying shellcode ==")
	p_mutex = p.add_mutually_exclusive_group(required=False)
	p.add_argument("-f", "--file", help="Enter path to file.", required=True)
	p.add_argument("-o", "--offset", help="Set hexadecimal program offset.", default="0x1000", required=False)
	p_mutex.add_argument("-t", "--test", help="Run and test compiled executable.", action='store_true', required=False)
	p.add_argument("-s", "--stdout", help="Check STDOUT for a specific string.", default="", required=False)
	p.add_argument("-se", "--stderr", help="Check STDERR for a specific string.", default="Segmentation fault", required=False)
	p_mutex.add_argument("-x", "--hexdump", help="Dump hex code.", action='store_true', required=False)
	p_mutex.add_argument("-c", "--compile", help="Compile file using C wrapper.", action='store_true', required=False)
	p_mutex.add_argument("-e", "--emulate", help="Emulate and analyse shellcode using Libemu.", action='store_true', required=False)
	p_mutex.add_argument("-d", "--disassemble", help="Disassemble shellcode.", action='store_true', required=False)
	p_mutex.add_argument("-a", "--assembler", help="Start ASM interactive assembler mode.", action='store_true', required=False)
	p_mutex.add_argument("-A", "--all", help="Run all functions above.", action='store_true', required=False)
	p_mutex.add_argument("-R", "--autorecompile", help="Automatic recompiling and testing upon file modification time change.", action='store_true', required=False)
	p.add_argument("-ob", "--objdump", help="Use Linux objdump instead of Python Capstone library.", action='store_true', required=False)
	args = p.parse_args(args)
	return args

# FUNCTIONS
def load_file(path):
	global file
	global shellcode
	global length
	file = open(path, "rb").read()
	x = bytes(file)
	shellcode = ''.join(r'\x'+hex(letter).upper()[2:].zfill(2) for letter in x)
	length = len(x)

def print_info(file):
	a = ("Filename = " + file + "\n")
	b = ("Length = " + str(length) + " bytes" + "\n\n")
	print (a + b)

def print_hex():
	print(format_text_green("Shellcode as escaped hex string: \n"))
	print(shellcode + "\n")

def disassemble_code(data,mode):
	if mode == 1:
		md = Cs(CS_ARCH_X86, CS_MODE_32 + CS_MODE_LITTLE_ENDIAN)
		md.detail = True
		print(format_text_green("ASM Code:"))
		print(format_text_green("Offset\t\tSize\tHex\t\t\tOpcode\tOperand"))
		for i in md.disasm(data, int(args.offset, 16)):
			hexcode = ''.join(hex(letter).upper()[2:].zfill(2) + " " for letter in i.bytes).ljust(16)
			print("%s\t%s\t%s\t%s\t%s" %(hex(i.address).ljust(8), str(i.size), hexcode, i.mnemonic, i.op_str))
	elif mode == 2:
		# Disassembly using objdump	
		print(format_text_green("Offset\tHex\t\tOpcode\tOperand"))
		disassembled = pipes.os.popen("objdump -D -Mintel,i386 -b binary -m i386 ./" + args.file + " | sed -e \'1,7d\'").read()
		print(disassembled)

def assemble_instruction(CODE):
	ks = Ks(KS_ARCH_X86, KS_MODE_32)
	encoding, count = ks.asm(CODE)
	code = ''.join(r'\x'+hex(letter).upper()[2:] for letter in encoding)
	print(code)

def disassemble_instruction(CODE):
	CODE = bytes.fromhex(CODE.replace('\\x', ''))
	md = Cs(CS_ARCH_X86, CS_MODE_32 + CS_MODE_LITTLE_ENDIAN)
	md.detail = True
	for i in md.disasm(CODE, 0x1000):
		print("%s\t%s" %(i.mnemonic, i.op_str))

def reset_terminal():
	os.system('clear')
	print(format_text_yellow("\n" + header() + "\n"))
	load_file(args.file)
	print_info(args.file)
	disassemble_code(file, mode)
	print(format_text_green("---------------------------------------"))
	print(format_text_green("Last Modified: " + time.ctime(os.path.getmtime(args.file))))

def assemble():
	CODE = input(format_text_yellow("asm > "))
	if CODE == "?":
		print("x86-instruction | recompile | test | emulate | ls | clear | exit")
	elif CODE.lower() == "recompile":
		recompile()
		print_green_line()
	elif CODE.lower() == "test":
		test_code()
		print_green_line()
	elif CODE.lower() == "ls":
		os.system('ls')
		print_green_line()
	elif CODE.lower() == "emulate":
		emulate_code(args.file)
		print_green_line()
	elif CODE.lower() == "reset":
		reset_terminal()
		print_green_line()
	elif CODE.lower() == "clear":
		reset_terminal()
		print_green_line()
	elif CODE.lower() == "exit":
		os._exit(1)
	elif CODE.lower() == "quit":
		os._exit(1)
	elif '\\x' in CODE:	
		disassemble_instruction(CODE)
	elif '0x' in CODE[:2]:	
		disassemble_instruction(CODE[2:])
	else:
		assemble_instruction(CODE)



def compile_code():
	c_wrapper = ('''
	#include<stdio.h>
	#include<string.h>
	
	unsigned char code[] = "{code}";
	
	main()
	{{
		printf(\"Shellcode Length:  %d\\n\", strlen(code));

		int (*ret)() = (int(*)())code;

		ret();
	}}''').format(code=shellcode)

	c_source = open(args.file + "_source.c", "w").write(c_wrapper)
	os.system("gcc -m32 -fno-stack-protector -z execstack " + args.file + "_source.c -o " + args.file + "_compiled 2> /dev/null")
	os.system("chmod +x " + args.file + "_compiled")

def test_code():
	test_file = "./" + args.file + "_compiled"
	stdout, stderr = Popen(test_file, shell=True, stdout=PIPE, stderr=PIPE).communicate()
	output = "STDOUT: "+ stdout.decode("utf-8")  + "\nSTDERR: " + stderr.decode("utf-8") 
	print(format_text_green("\n---------------------------------------\nProgram Execution: "))
	print(output)
	if args.stdout != "":
		print("Test String = " + str(args.stdout))
	if str(args.stderr).lower() in str(stderr).lower():
		print(format_text_red("\nTEST FAILED"))
	elif str(args.stdout).lower() in str(stdout).lower():
		print(format_text_green("\nTEST SUCCESSFUL"))
	else:
		print(format_text_red("\nTEST FAILED"))


def check_string():
	if args.stdout == None:
		print("Enter a test string with the -s option. \nEnter empty string if necessary.")

def recompile():
	os.system('clear')
	print(format_text_yellow("\n" + header() + "\n"))
	load_file(args.file)
	print_info(args.file)
	disassemble_code(file, mode)
	compile_code()
	print(format_text_green("Last Modified: " + time.ctime(os.path.getmtime(args.file))))

def emulate_code(file):
	print(format_text_green("\nShellcode emulated:"))
	pipes.quote(os.popen("cat " + file + " | sctest -vvv -Ss 100000 -G " + file + ".dot").read())
	pipes.quote(os.popen("dot " + file + ".dot -Tpng -o " + file + ".png").read())
	print("Diagram saved as \'" +  file + ".dot\' & \'" + file + ".png\'")

# FUNCTION LOOPS
def assembler_loop():
	while True:
		try:
			assemble()
		except KsError:
			pass
		except TypeError:
			pass
		except ValueError:
			pass
		except KeyboardInterrupt:
			os._exit(1)

def recompiler_loop():
	timestamp = time.ctime(os.path.getmtime(args.file))
	while True:
		try:
			time.sleep(1)
			if timestamp != time.ctime(os.path.getmtime(args.file)):
				recompile()
				test_code()
				print("\nPress the 'Enter' key to start the Assembler")
				timestamp = time.ctime(os.path.getmtime(args.file))
		except KeyboardInterrupt:
			os._exit(1)

# ADD CMD SUPPORT
try:
    import readline
except:
    pass

# FORMATTING
def format_text_red(title):
    cr = '\r\n'
    section_break = cr + "*" * 20 + cr
    text = Style.BRIGHT + Fore.RED + title + Fore.RESET
    return text;

def format_text_yellow(title):
    cr = '\r\n'
    section_break = cr + "*" * 20 + cr
    text = Style.BRIGHT + Fore.YELLOW + title + Fore.RESET
    return text;

def format_text_green(title):
    cr = '\r\n'
    section_break = cr + "*" * 20 + cr
    text = Style.BRIGHT + Fore.GREEN + title + Fore.RESET
    return text;

def header():
	banner = "=============================================================\n                -- Shellcode Assistant v1.0 --\n============================================================="
	return(banner)

def print_green_line():
	print(format_text_green("---------------------------------------"))

# MAIN METHOD
if __name__ == '__main__':
	print(format_text_yellow("\n" + header() + "\n"))
	args = cli_options()
	# Disassembly Mode (1 = Python Capstone, 2 = Objdump)
	if args.objdump == False:
		mode = 1
	elif args.objdump == True:
		mode = 2
	if args.file:
		load_file(args.file)
		print_info(args.file)
	if args.hexdump and args.file:
		print_hex()
	if args.file and args.disassemble:
		disassemble_code(file,mode)
	if args.file and args.compile:
		compile_code()
	if args.file and args.test:
		test_code()
		check_string()
	if args.file and args.emulate:
		emulate_code(args.file)
	if args.file and args.all:
		print_hex()
		disassemble_code(file,mode)
		compile_code()
		emulate_code(args.file)
		test_code()
		check_string()
		assembler_loop()
	if args.file and args.autorecompile:
		disassemble_code(file, mode)
		compile_code()
		test_code()
		timestamp = time.ctime(os.path.getmtime(args.file))
		print(format_text_green("Last Modified: " + timestamp))
		print(format_text_green("---------------------------------------"))
		thread1 = threading.Thread(target=assembler_loop)
		thread1.start()
		thread2 = threading.Thread(target=recompiler_loop)
		thread2.start()
	if args.file and args.assembler and not args.autorecompile:
		print(format_text_green("---------------------------------------"))
		assembler_loop()



