title: "fPIC"
date: 2015-06-15 14:54:41
tags: C 
---

###Introduction to PIC - (Position Independent Code)

PIC code differs from traditional code in the method it will perform access to function code and data objects/variables through an indirect accessing table. This table is called the "Global Offset Table" because it contains the addresses of code functions and data objects exported by a shared library.

The dynamic loader modifies the GOT slots to resemble the current memory address for every exported symbol in the library. When the dynamic loader has completed, the GOT contains full absolute addresses for each symbol reference constructed from the load address (PT_LOAD) of the shared library that contains these symbols plus their offset inside this shared library. 

### shared library
一般編譯 shared library 都會加上 -fPIC
``` bash
gcc a.c -o -fPIC
gcc b.c -o -fPIC
gcc --shared -o libab.so a.o b.o
```

###The Global Offset Table (GOT)
GOT 位於 data section，保存 symbol address 的表格。

###The Procedure Linkage Table (PLT)

###Position Independent Code(PIC)
主要的關鍵是取得 text section 和 data section的位移，text section 會緊跟在 data section 之後，所以給定一個在 text section 中的指令，那麼這個指令到 data section 的開頭的位移就是 text section 的大小減去指令在text section裡的位移。
算出了 offset 要取得 data section裡的資料，需要 instruction 的位址，但 x86 沒有取得 EIP 的指令，所以可以利用一些方法取得：
```asm
        call label
label:
        pop ebx
``` 
1. call 會把下一行指令的位址 push 到 stack。
2. 跳到 label。
3. stack pop 到 ebx register，ebx 就是 label 所在的位址。

```asm
; 1. Somehow get the address of the GOT into ebx
lea ebx, ADDR_OF_GOT

; 2. Suppose ADDR_OF_VAR is stored at offset 0x10
;    in the GOT. Then this will place ADDR_OF_VAR
;    into edx.
mov edx, DWORD PTR [ebx + 0x10]

; 3. Finally, access the variable and place its
;    value into edx.
mov edx, DWORD PTR [edx]
```
藉由 GOT 來 relocation 避免在 text section 進行，如此 text section 就可以是 read-only 並且共享。比起在 text section 作 relocation，GOT 只需對一個變數進行，因此較有效率。

### Example
```c
int _foo;

void set_foo(int foo)
{
        _foo = foo;
}

int get_foo()
{
        return _foo;
}

```

```asm
0000054c <set_foo>:
 54c:   55                      push   %ebp
 54d:   89 e5                   mov    %esp,%ebp
 54f:   e8 2b 00 00 00          call   57f <__x86.get_pc_thunk.cx>
 554:   81 c1 ac 1a 00 00       add    $0x1aac,%ecx
 55a:   8b 81 f4 ff ff ff       mov    -0xc(%ecx),%eax
 560:   8b 55 08                mov    0x8(%ebp),%edx
 563:   89 10                   mov    %edx,(%eax)
 565:   5d                      pop    %ebp
 566:   c3                      ret 

0000057f <__x86.get_pc_thunk.cx>:
 57f:   8b 0c 24                mov    (%esp),%ecx
 582:   c3                      ret    
 583:   90                      nop
```

+ 在 0x54f，call 了 <__x86.get_pc_thunk.cx>，ecx 的值會是0x554。
+ ecx 再加上 0x1aac，取得 GOT的位址(0x2000)。
+ ecx - 0xc 就是 _foo 的位址，被放到 eax裡。
+ 在0x560，把 foo 的值放到 edx。
+ 在0x563，更新 eax 位址的值為edx。

使用 readelf 來看看 GOT 的位址
```bash
readelf -S libfoo.so
Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  ...
  [19] .got              PROGBITS        00001fe8 000fe8 000018 04  WA  0   0  4
  [20] .got.plt          PROGBITS        00002000 001000 000014 04  WA  0   0  4
```
這裡看到 0x2000 是 .got.plt 的位址，0x2000 - 0xc = 0x1ff4 為 _foo 的位址。

```bash
readelf -r libfoo.so

Relocation section '.rel.dyn' at offset 0x374 contains 9 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
00001ef4  00000008 R_386_RELATIVE   
00001ef8  00000008 R_386_RELATIVE   
00002014  00000008 R_386_RELATIVE   
00001fe8  00000106 R_386_GLOB_DAT    00000000   _ITM_deregisterTMClone
00001fec  00000206 R_386_GLOB_DAT    00000000   __cxa_finalize
00001ff0  00000306 R_386_GLOB_DAT    00000000   __gmon_start__
00001ff4  00000d06 R_386_GLOB_DAT    0000201c   _foo
```
### Function calls in PIC

***
+ fPIC
+ fpic

***
[PIC](http://reborn2266.blogspot.tw/2011/11/position-independent-code-pic-in-shared.html)

http://eli.thegreenplace.net/2011/08/25/load-time-relocation-of-shared-libraries/
https://wiki.gentoo.org/wiki/Hardened/Position_Independent_Code_internals
http://eli.thegreenplace.net/2011/11/03/position-independent-code-pic-in-shared-libraries/
http://fcamel-life.blogspot.tw/2012/11/shared-library-visibility.html