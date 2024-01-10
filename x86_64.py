from zydis import *
import zyan

with open("termsrv.dll", "rb") as file:
    data = file.read()

bServerSku_addr = None
bRemoteConnAllowed_addr = None
bFUSEnabled_addr = None
bAppServerAllowed_addr = None
bMultimonAllowed_addr = None
lMaxUserSessions_addr = None
ulMaxDebugSessions_addr = None
bInitialized_addr = None

def on_instruction(instruction, runtime_address, user_data):
    operands = instruction.operands
    current = user_data

    if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA and
        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY and
        operands[1].mem.base == ZYDIS_REGISTER_RIP and
        operands[1].mem.disp.has_displacement == ZYAN_TRUE and
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER and
        operands[0].reg.value == ZYDIS_REGISTER_RDX):

        DWORD64 target = operands[1].mem.disp.value + runtime_address - data.buffer_info().buf
        if target == bRemoteConnAllowed_addr: current = &bRemoteConnAllowed_addr;
        else if (target == bFUSEnabled_addr) current = &bFUSEnabled_addr;
        else if (target == bAppServerAllowed_addr) current = &bAppServerAllowed_addr;
        else if (target == bMultimonAllowed_addr) current = &bMultimonAllowed_addr;
        else if (target == lMaxUserSessions_addr) current = &lMaxUserSessions_addr;
        else if (target == ulMaxDebugSessions_addr) current = &ulMaxDebugSessions_addr;

    elif (instruction.mnemonic == ZYDIS_MNEMONIC_MOV and
        operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY and
        operands[0].mem.base == ZYDIS_REGISTER_RIP and
        operands[0].mem.disp.has_displacement == ZYAN_TRUE and
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER and
        operands[1].reg.value == ZYDIS_REGISTER_EAX):
        bInitialized_addr = operands[0].mem.disp.value + runtime_address - data.buffer_info().buf

zydis_decoder_init(decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64BIT)
zydis_decoder_decode_buffer(decoder, data, len(data), runtime_address, on_instruction, current)

print(f"bServerSku.x64={bServerSku_addr:X}")
print(f"bRemoteConnAllowed.x64={bRemoteConnAllowed_addr:X}")
print(f"bFUSEnabled.x64={bFUSEnabled_addr:X}")
print(f"bAppServerAllowed.x64={bAppServerAllowed_addr:X}")
print(f"bMultimonAllowed.x64={bMultimonAllowed_addr:X}")
print(f"lMaxUserSessions.x64={lMaxUserSessions_addr:X}")
print(f"ulMaxDebugSessions.x64={ulMaxDebugSessions_addr:X}")
print(f"bInitialized.x64={bInitialized_addr:X}")
