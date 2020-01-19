## IDA_MIPS_EMU

a IDA plugin, use for emulating mips code and patch function/code in IDA pro. 

### Install

```
sudo pip install unicorn --user
```

### Usage

- begin emulating: 
```
a = EmuMips()
a.configEmu(0x400000,0x401000,[1,2,3])              # set startaddr,endaddr and paramters

a.beginEmu()
a.showRegs()
```

- fill data

fill data into addr 0x401000
```
a.fillData("test123",0x401000)

Python>a.fillData("MTIzNDUK",0xbfffe000)
[*] Data mapping address： 0xbfffe000
```

- read content from memory address

```
a.readMemContent(0x10008000,[size])

Python>a.readMemContent(0xbfffe000,50)
[*] Dest memory content: MTIzNDUK
```

- show registers content

```
a.showRegs()

Python>a.showRegs()
[*]  regs: 
[*]     A0 = 0xbfffe000  A1 = 0x8  A2 = 0xbffff000
        SP = 0xbfff8000  RA = 0x0  FP = 0x0
```

- show hook info

```
a.showTrace()

>>> Tracing instruction at 0x4435a4, instruction size = 0x4
>>> Tracing instruction at 0x4435a8, instruction size = 0x4
>>> Tracing instruction at 0x4435ac, instruction size = 0x4
>>> Tracing instruction at 0x4435b0, instruction size = 0x4
>>> Tracing instruction at 0x4435b4, instruction size = 0x4
...
```

### Example


- source code

```
#include <stdlib.h>

int calc(int a,int b){
        int sum;
        sum = a+b;
        return sum;

}

int main(){
        cala(2,3);
}
```

- calc function

```
.text:00400640                 .globl calc
.text:00400640 calc:                                    # CODE XREF: main+18↓p
.text:00400640
.text:00400640 var_10          = -0x10
.text:00400640 var_4           = -4
.text:00400640 arg_0           =  0
.text:00400640 arg_4           =  4
.text:00400640
.text:00400640                 addiu   $sp, -0x18
.text:00400644                 sw      $fp, 0x18+var_4($sp)
.text:00400648                 move    $fp, $sp
.text:0040064C                 sw      $a0, 0x18+arg_0($fp)
.text:00400650                 sw      $a1, 0x18+arg_4($fp)
.text:00400654                 lw      $v1, 0x18+arg_0($fp)
.text:00400658                 lw      $v0, 0x18+arg_4($fp)
.text:0040065C                 addu    $v0, $v1, $v0
.text:00400660                 sw      $v0, 0x18+var_10($fp)
.text:00400664                 lw      $v0, 0x18+var_10($fp)
.text:00400668                 move    $sp, $fp
.text:0040066C                 lw      $fp, 0x18+var_4($sp)
.text:00400670                 addiu   $sp, 0x18
.text:00400674                 jr      $ra
.text:00400678                 nop
.text:00400678  # End of function calc
```

- IDA emu

- before run the script, two space must be modified, the second parameter of the GetManyBytes function in line 32, which must be changed to the size of the code segment, the result value of getModeFromIDA function must be replaces big or little endian.

1. Create a emu object

```
Python>a = EmuMips()

```

2. Configure address and registers

```
Python>a.configEmu(0x00400640,0x00400678,[2,3])
[*] Init registers success...
[*] Init code and data segment success! 
[*] Init Stack success...
[*] set args...
```


3. Show registers info

```
Python>a.showRegs()
[*]  regs: 
[*]     A0 = 0x2  A1 = 0x3  A2 = 0x0
        SP = 0xbfff8000  RA = 0x0  FP = 0x0  V0 = 0x0
```

4. Start emulate

```
Python>a.beginEmu()
[*] emulating...

[*] Done! Emulate result return: 0x5
```

5. print result 

```
Python>a.showRegs()
[*]  regs: 
[*]     A0 = 0x2  A1 = 0x3  A2 = 0x0
        SP = 0xbfff8000  RA = 0x0  FP = 0x0  V0 = 0x5
```

- 2+3 = 5, the result stored in v0 register

### other functions

1. set register value 

```
setRegValue("a0",1)
```

2. map new memory

- default mapping 0x1000 space

```
mapNewMemory(0x1000)
```
