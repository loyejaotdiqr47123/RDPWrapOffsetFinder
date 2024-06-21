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