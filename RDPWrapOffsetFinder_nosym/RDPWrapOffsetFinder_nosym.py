import pefile

Query = "CDefPolicy::Query"
LocalOnly = "CSLQuery::IsTerminalTypeLocalOnly"
SingleSessionEnabled = "CSessionArbitrationHelper::IsSingleSessionPerUserEnabled"
InstanceOfLicense = "CEnforcementCore::GetInstanceOfTSLicense"

AllowRemote = u"TerminalServices-RemoteConnectionManager-AllowRemoteConnections"
AllowMultipleSessions = u"TerminalServices-RemoteConnectionManager-AllowMultipleSessions"
AllowAppServer = u"TerminalServices-RemoteConnectionManager-AllowAppServerMode"
AllowMultimon = u"TerminalServices-RemoteConnectionManager-AllowMultimon"
MaxUserSessions = u"TerminalServices-RemoteConnectionManager-MaxUserSessions"
MaxDebugSessions = u"TerminalServices-RemoteConnectionManager-ce0ad219-4670-4988-98fb-89b14c2f072b-MaxSessions"

def find_section(pe, section_name):
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == section_name:
            return section
    return None

def pattern_match(pe, section_name, pattern):
    section = next((s for s in pe.sections if s.Name.rstrip(b'\x00').decode() == section_name), None)
    if not section:
        return -1

    rdata = section.PointerToRawData
    size_of_raw_data = section.SizeOfRawData
    
    if isinstance(pattern, str):
        pattern = pattern.encode()
    pattern_size = len(pattern)
    
    section_data = pe.get_memory_mapped_image()[rdata:rdata + size_of_raw_data]
    
    for i in range(0, size_of_raw_data - pattern_size + 1, 4):
        if section_data[i:i + pattern_size] == pattern:
            return section.VirtualAddress + i

    return -1

def searchXref(pe_file_path, function_rva, target_offset):
    pe = pefile.PE(pe_file_path)

    for section in pe.sections:
        if (section.Characteristics & 0x20000000):
            section_start = section.VirtualAddress
            section_end = section_start + section.SizeOfRawData
            break
    else:
        raise ValueError("No executable section found in the PE file")

    function_rva = function_rva - pe.OPTIONAL_HEADER.ImageBase

    section_data = pe.get_memory_mapped_image()[section_start:section_end]

    lea_pattern = b'\x48\x8d'

    index = section_data.find(lea_pattern)
    while index != -1:
        displacement_offset = index + 3
        displacement_value = int.from_bytes(section_data[displacement_offset:displacement_offset + 4], byteorder='little')
        
        if displacement_value + index + section_start == target_offset + section_start:
            return index + section_start
        
        index = section_data.find(lea_pattern, index + 1)

    return 0 

def backtrace(base, func, pe):
    while func.UnwindData & pefile.UNW_FLAG_CHAININFO:
        if func.UnwindData & pefile.RUNTIME_FUNCTION_INDIRECT:
            func = pe.get_runtime_function(base + (func.UnwindData & ~3))
        else:
            func = pe.get_runtime_function(base + func.UnwindData)
        
        unwind_info_rva = func.UnwindData
        unwind_info = pe.get_struct('UNWIND_INFO', unwind_info_rva)
    
    return func

def findImportImage(pe, dll_name):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.decode().lower() == dll_name.lower():
            return entry
    return None
