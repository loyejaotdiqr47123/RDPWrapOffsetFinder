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
