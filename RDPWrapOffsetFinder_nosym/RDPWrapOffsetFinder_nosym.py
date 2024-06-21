import pefile
from capstone import *

Query = "CDefPolicy::Query"
LocalOnly = "CSLQuery::IsTerminalTypeLocalOnly"
SingleSessionEnabled = "CSessionArbitrationHelper::IsSingleSessionPerUserEnabled"
InstanceOfLicense = "CEnforcementCore::GetInstanceOfTSLicense "

AllowRemote = "TerminalServices-RemoteConnectionManager-AllowRemoteConnections"
AllowMultipleSessions = "TerminalServices-RemoteConnectionManager-AllowMultipleSessions"
AllowAppServer = "TerminalServices-RemoteConnectionManager-AllowAppServerMode"
AllowMultimon = "TerminalServices-RemoteConnectionManager-AllowMultimon"
MaxUserSessions = "TerminalServices-RemoteConnectionManager-MaxUserSessions"
MaxDebugSessions = "TerminalServices-RemoteConnectionManager-ce0ad219-4670-4988-98fb-89b14c2f072b-MaxSessions"

def find_section_by_name(pe_file_path, section_name):
    # 将节名称转换为小写，以进行不区分区域设置的比较
    section_name = section_name.lower()
    
    # 使用pefile库解析PE文件
    pe = pefile.PE(pe_file_path)
    
    for section in pe.sections:
        # 将节的名称转换为小写进行比较
        if section.Name.decode().rstrip('\x00').lower() == section_name:
            return section  # 返回指向该节头的指针（即section对象）
    
    return None

def find_pattern_in_pe(pe_file, pattern):
    pe = pefile.PE(pe_file, fast_load=True)
        
    for section in pe.sections:
        # 获取内存区段的虚拟地址和大小
        virtual_addr = section.VirtualAddress
        size_of_data = section.SizeOfRawData
            
        # 读取内存区段的内容
        pe_file.seek(section.PointerToRawData)
        data = pe_file.read(size_of_data)
            
        # 在内存区段中搜索字节模式
        offset = data.find(pattern)
        if offset != -1:
            return virtual_addr + offset
        
        # 如果没有找到匹配的字节模式，返回-1
    
    return -1

def find_lea_instruction(target_address, function_code):
    # 初始化Capstone反汇编器
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True  # 启用指令详细信息

    # 遍历函数代码中的指令
    for insn in md.disasm(function_code, 0):
        # 检查指令是否为LEA（加载有效地址）指令
        if insn.mnemonic == 'lea':
            # 遍历LEA指令的操作数
            for op in insn.operands:
                # 确保操作数是内存引用
                if op.type == X86_OP_MEM:
                    # 检查内存偏移是否与目标地址匹配
                    if op.mem.disp == target_address:
                        return insn  # 如果找到匹配的LEA指令，则返回

    return None  # 如果未找到匹配的LEA指令，则返回None

def search_xref(base, function_start, function_end, target):
    # 初始化Capstone解码器
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)  # 假设我们处理的是64位x86架构
    md.detail = True  # 设置为True以获取更详细的解码信息

    # 设置解码器的语法
    md.syntax = cs.CS_OPT_SYNTAX_ATT

    # 计算函数的大小
    function_size = function_end - function_start

    # 遍历函数的字节码
    ip = function_start
    while ip < function_end:
        # 解码下一条指令
        code = base + ip
        instructions = md.disasm(bytearray(memoryview(code)[:function_size]), ip)

        # 遍历解码后的指令
        for insn in instructions:
            # 检查助记符是否为LEA
            if insn.mnemonic == 'lea':
                # 检查操作数
                for operand in insn.operands:
                    if operand.type == cs.x86.X86_OP_MEM:
                        # 检查操作数是否是基于RIP的
                        if operand.mem.base == cs.x86.X86_REG_RIP:
                            # 计算LEA指令的目标地址
                            lea_target = insn.address + insn.size + operand.mem.disp

                            # 检查LEA指令的目标地址是否等于目标地址
                            if lea_target == target:
                                return insn.address - base  # 返回LEA指令的地址

        # 移动到下一条指令
        ip += insn.size

    return None

import struct
import ctypes

# 定义相关结构体
class RUNTIME_FUNCTION(struct.Structure):
    _fields_ = [
        ("BeginAddress", ctypes.c_uint32),
        ("EndAddress", ctypes.c_uint32),
        ("UnwindData", ctypes.c_uint32),
    ]

class UNWIND_INFO(struct.Structure):
    _fields_ = [
        ("Version", ctypes.c_uint8),
        ("Flags", ctypes.c_uint8),
        ("SizeOfProlog", ctypes.c_uint16),
        ("CountOfCodes", ctypes.c_uint32),
        ("FrameRegister", ctypes.c_uint32),
        ("FrameOffset", ctypes.c_uint32),
        ("UnwindCode", ctypes.c_uint32 * 1),
    ]

RUNTIME_FUNCTION_INDIRECT = 0x1
UNW_FLAG_CHAININFO = 0x4

def backtrace(base, func):
    if func.UnwindData & RUNTIME_FUNCTION_INDIRECT:
        func = RUNTIME_FUNCTION.from_address(base + (func.UnwindData & ~3))

    unwind_info = UNWIND_INFO.from_address(base + func.UnwindData)

    while unwind_info.Flags & UNW_FLAG_CHAININFO:
        func = RUNTIME_FUNCTION.from_address(base + unwind_info.UnwindCode[unwind_info.CountOfCodes + 1 & ~1])
        unwind_info = UNWIND_INFO.from_address(base + func.UnwindData)

    return func
