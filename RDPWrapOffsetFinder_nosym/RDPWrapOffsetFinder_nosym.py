import pefile

def find_section_by_name(pe_file_path, section_name):
    # 将节名称转换为小写，以进行不区分区域设置的比较
    section_name = section_name.lower()
    
    # 使用pefile库解析PE文件
    pe = pefile.PE(pe_file_path)
    
    for section in pe.sections:
        # 将节的名称转换为小写进行比较
        if section.Name.decode().rstrip('\x00').lower() == section_name:
            return section  # 返回指向该节头的指针（
    
    return None