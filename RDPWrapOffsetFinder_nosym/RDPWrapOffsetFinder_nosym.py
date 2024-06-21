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