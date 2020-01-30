# coding: utf-8
# __Author__: H4lo
from __future__ import print_function
from unicorn import *
from unicorn.mips_const import *
from idaapi import *

CODE_ADDR = None
CODE_SIZE = 0x100000

STACK_ADDR = 0xbfff0000
STACK_SIZE = 0x10000

DATA_ADDR = 0x10000000
DATA_SIZE = 0x10000



class EmuMips(object):
    def __init__(self):

        self.stack = STACK_ADDR
        self.stack_size = STACK_SIZE
        #self.start
        self.regs = dict()
        self.uc = None
        self.DEBUG_INFO = ""
        self.startAddr = None
        self.endAddr = None
        print("[+] Init...")

    def getTextSegmentSize(self):
        '''
        for seg in idautils.Segments():
            if idc.SegName(seg) == ".text":
                return(idc.SegEnd(seg)-get_imagebase())
        '''
        mapSize = (get_inf_structure().get_maxEA() - get_inf_structure().get_minEA())
        return mapSize


    def initCodeAndData(self):
        CODE_ADDR = get_imagebase()                                 # set CODE_ADDR equal with image base
        code_bytes = GetManyBytes(CODE_ADDR,self.getTextSegmentSize())                # default mapping 0x10000 space 
        self.uc.mem_map(CODE_ADDR,CODE_SIZE)
        self.uc.mem_write(CODE_ADDR,code_bytes)

        self.uc.mem_map(DATA_ADDR,DATA_SIZE)

        self.printInfo("Init code and data segment success! ")
    
    def initRegs(self):
        
        self.regs['a0'] = UC_MIPS_REG_A0

        #reg_read(UC_MIPS_REG_A0)
        self.regs['a1'] = UC_MIPS_REG_A1
        self.regs['a2'] = UC_MIPS_REG_A2
        self.regs['sp'] = UC_MIPS_REG_SP
        self.regs['ra'] = UC_MIPS_REG_RA
        self.regs['fp'] = UC_MIPS_REG_FP
        self.regs['v0'] = UC_MIPS_REG_V0

        for reg_k,reg_v in self.regs.items():
            self.uc.reg_write(reg_v,0)                                      # init registers

        #self.uc.reg_write(self.regs['a2'],0x4f1390)

        self.printInfo("Init registers success...")
        

    def initStack(self):
        self.uc.mem_map(STACK_ADDR,STACK_SIZE)                              # map and set stack space
        self.uc.reg_write(self.regs['sp'],STACK_ADDR+STACK_SIZE-0x800)
        self.uc.reg_write(self.regs['fp'],STACK_ADDR+STACK_SIZE-0x800)

        self.printInfo("Init Stack success...")

    def showRegs(self):                                 # handle call
        regs_list = []
        self.printInfo(" regs: ")
        #print(self.regs)
        for reg_k,reg_v in self.regs.items():
            #print(reg_k)
            regs_list.append(self.uc.reg_read(reg_v))
        self.printInfo("    A0 = 0x%x  A1 = 0x%x  A2 = 0x%x\n        SP = 0x%x  RA = 0x%x  FP = 0x%x  V0 = 0x%x\n"% (
                regs_list[4],regs_list[3],regs_list[5],regs_list[2],regs_list[6],regs_list[0],regs_list[1]))

    def readMemContent(self,address,size=100):
        content = self.uc.mem_read(address,size)
        self.printInfo("Dest memory content: %s" % (content))


    def printInfo(self,info):
        print("[*] {inf}".format(inf=info))

    def showTrace(self):
        print(self.DEBUG_INFO)

    def fillData(self,data,addr = DATA_ADDR+DATA_SIZE/2):                             # handle call
        default_map_addr = DATA_ADDR+DATA_SIZE/2
        if ((data != None) and (addr == DATA_ADDR+DATA_SIZE/2)):
            self.uc.mem_write(default_map_addr,data)
            self.printInfo("Data mapping address： 0x%x"% (default_map_addr))
        if (addr != DATA_ADDR+DATA_SIZE/2):
            self.uc.mem_write(addr,data)
            self.printInfo("Data mapping address： 0x%x"% (addr))
        #print(1)

    def setRegValue(self,reg_name,value):
        self.uc.reg_write(self.regs[reg_name],value)
        self.printInfo("Write register success!")

    def mapNewMemory(self,mem_addr,size=0x1000):
        self.uc.mem_map(mem_addr,size)
        self.uc.mem_write(mem_addr,"\x00"*size)
        self.printInfo("Map memory success!")

    def hook_code(self,uc, address, size, user_data):
        self.DEBUG_INFO += ">>> Tracing instruction at 0x%x, instruction size = 0x%x\n" %(address, size)
        #print("AAAA")

    def getArchFromIDA(self):                           # get arch and endian information from IDA, api: idaapi.get_inf_structure()
        return UC_ARCH_MIPS

    def getModeFromIDA(self):
        #return UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN
        if get_inf_structure().is_be():                 # executable file is big endian
            return UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN
        else:
            return UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN

    def parseParams(self,args):
        try:
            self.printInfo("set args...")
            
            self.uc.reg_write(self.regs['a0'],args[0])

            self.uc.reg_write(self.regs['a1'],args[1])
            self.uc.reg_write(self.regs['a2'],args[2])
        except Exception as e:
            pass

    def configEmu(self,startAddr,endAddr,args=[]):
        arch = self.getArchFromIDA()
        mode = self.getModeFromIDA()

        self.uc = Uc(arch,mode)
        self.initRegs()
        self.initCodeAndData()
        self.initStack()
        
        self.uc.hook_add(UC_HOOK_CODE,self.hook_code)

        self.startAddr = startAddr
        self.endAddr = endAddr

        self.parseParams(args)
        #self.beginEmu(startAddr,endAddr)

    def beginEmu(self):
        startAddr = self.startAddr
        endAddr = self.endAddr
        self.printInfo("emulating...\n")
        try:
            self.uc.emu_start(startAddr,endAddr)

            emu_result = self.uc.reg_read(self.regs['v0'])               # result value

            self.printInfo("Done! Emulate result return: 0x%x" % (emu_result))
        except UcError as e:
            self.printInfo("ERROR: {e}".format(e=e))

    def patchFunc(self,callFuncAddr_list):                              # patch fucntions to `nop`
        for callFuncAddr in callFuncAddr_list:
            self.uc.mem_write(callFuncAddr,"\x00\x00\x00\x00")
        
        self.printInfo("Patch function success! ")


    def fuzzFunc(self,data):
        print(1)

banner = '''
$$$$$$\$$$$$$$\  $$$$$$\       $$\      $$\$$$$$$\$$$$$$$\  $$$$$$\      $$$$$$$$\$$\      $$\$$\   $$\ 
\_$$  _$$  __$$\$$  __$$\      $$$\    $$$ \_$$  _$$  __$$\$$  __$$\     $$  _____$$$\    $$$ $$ |  $$ |
  $$ | $$ |  $$ $$ /  $$ |     $$$$\  $$$$ | $$ | $$ |  $$ $$ /  \__|    $$ |     $$$$\  $$$$ $$ |  $$ |
  $$ | $$ |  $$ $$$$$$$$ |     $$\$$\$$ $$ | $$ | $$$$$$$  \$$$$$$\      $$$$$\   $$\$$\$$ $$ $$ |  $$ |
  $$ | $$ |  $$ $$  __$$ |     $$ \$$$  $$ | $$ | $$  ____/ \____$$\     $$  __|  $$ \$$$  $$ $$ |  $$ |
  $$ | $$ |  $$ $$ |  $$ |     $$ |\$  /$$ | $$ | $$ |     $$\   $$ |    $$ |     $$ |\$  /$$ $$ |  $$ |
$$$$$$\$$$$$$$  $$ |  $$ |     $$ | \_/ $$ $$$$$$\$$ |     \$$$$$$  |    $$$$$$$$\$$ | \_/ $$ \$$$$$$  |
\______\_______/\__|  \__$$$$$$\__|     \__\______\__|      \______$$$$$$\________\__|     \__|\______/ 
                         \______|                                  \______|                                                                                                                             

'''
print("="*0x68)
print(banner)
print("="*0x68)
#a = EmuMips()
#a.configEmu(0x1000,0x2000)
