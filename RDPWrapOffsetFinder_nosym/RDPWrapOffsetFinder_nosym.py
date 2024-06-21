import pefile
from capstone import *

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
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    for insn in md.disasm(function_code, 0):
        if insn.mnemonic == 'lea':
            for op in insn.operands:
                if op.type == X86_OP_MEM:
                    if op.mem.disp == target_address:
                        return insn

    return None