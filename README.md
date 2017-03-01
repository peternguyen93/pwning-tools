# *pwning-tools*
## Author : _peternguyen_
## Version : _2.0 beta_
## Requirements:
- capstone
- keystone
- pyelftools
## Installation:
- > $./install.sh
## Description :
- *pwning-tools* is a minimal library including many feature that help CTFer create a simple, fast exploit payload in CTF competition.
- *pwning-tools* support parsing elf file to extract some usefull information such as : GOT, PLT and other symbol by passing elf file into elf argument:
```python >>> from Pwn import *
>>> p = Pwn(elf='./silver_bullet')
>>> p.elf.got
{'usleep': 134524888, 'strncat': 134524924, 'stdin': 134524960, '__gmon_start__': 134524896, 'puts': 134524892, 'stdout': 134524964, 'read': 134524880, 'memset': 134524916, 'atoi': 134524920, 'exit': 134524900, 'printf': 134524884, '__libc_start_main': 134524908, 'strlen': 134524904, 'setvbuf': 134524912}
```
- *pwning-tools* support interact with network socket and process (only work in Linux):
```python
>>> from Pwn import *
>>> p = Pwn(elf='./silver_bullet',lazy='target 4444') # for socket
>>> p = PwnProc(elf='./silver_bullet') # for interact with process
```
- *pwning-tools* provides some method that help pwner easier to find libc symbol when they have leak address
```python
>>> from Pwn import *
>>> p = Pwn()
>>> offset,offset2 = p.get_libc_offset(0x7ffff7a84e30,'puts',is_get_base=True)
>>> print hex(offset)
0x297f0
>>> base_address = 0x7ffff7a84e30 - offset2
>>> print hex(base_address)
0x7ffff7a15000
>>> offset = p.get_libc_offset(0x7ffff7a84e30,'puts')
>>> print hex(offset)
0x297f0
```
- *pwning-tools* provides a method in PwnProc that help pwner can convert script running with pwning-tools in to standalone script can run separate in target server.
```python
>>> p = PwnProc(elf='./hunting')
>>> # some pwn code
>>> p.export('./standalone_hunting.py')
```
- *pwning-tool* provides *Shellcode* that have some default shellcode for pwning also support some function that help pwner can quickly write shellcode in python script.