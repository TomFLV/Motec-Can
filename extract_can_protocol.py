#!/usr/bin/env python3
"""
Extract CAN Protocol from MoTeC PDM Manager and Firmware
"""
import re
import struct
import os

# ============================================================================
# Known Protocol Constants (from reverse engineering)
# ============================================================================

# CAN IDs for normal operation (from .pdm config files)
RUNTIME_CAN = {
    "INPUT_BASE": 280,      # 0x118 - Messages FROM ECU to PDM
    "OUTPUT_BASE": 1280,    # 0x500 - Status messages FROM PDM
    "CUSTOM_MSG_BASE": 1312 # 0x520 - Custom user messages
}

# CAN IDs for PC communication (from binary analysis)
PC_COMM_CAN = {
    "REQUEST_ID": 0x7E0,    # PC -> PDM (diagnostic request)
    "RESPONSE_ID": 0x7E8,   # PDM -> PC (diagnostic response)
    # Alternative rebased IDs: 0x600 + (serial % 16) * 0x10
}

# Operation codes (extracted from strings)
OPERATIONS = [
    "OpBeginRx",
    "OpCheckHalt",
    "OpClearHalt", 
    "OpClearStay",
    "OpEndRx",
    "OpGetChannels",
    "OpGetConfigStatus",
    "OpGetCopyright",
    "OpGetFirmwareStatus",
    "OpGetFirmwareVersionDevice",
    "OpGetFirmwareVersionFile",
    "OpGetHWId",
    "OpGetHWNum",
    "OpGetLockStatus",
    "OpGetPCData",
    "OpGetSerial",
    "OpGetSerialNum",
    "OpGetVersion",
    "OpGetVersionMajor",
    "OpReadCalibration",
    "OpReadTestStatus",
    "OpRebase",
    "OpRelock",
    "OpReset",
    "OpResetAndStay",
    "OpSetAllPasswords",
    "OpSetBitrate",
    "OpSetHalt",
    "OpSetHeartbeat",
    "OpUnlock",
    "OpUnlockConfig",
    "OpUnlockFirmware",
    "OpUnRebase",
    "OpVerifyFirmwareStatus",
    "OpVerifyPDMType",
    "OpWriteCalibration",
    "OpWriteConfig",
    "OpWriteFirmware",
    "OpWriteOutputTestControl",
]

def analyze_firmware_can():
    """Analyze firmware for CAN message handling"""
    print("="*70)
    print("FIRMWARE CAN ANALYSIS")
    print("="*70)
    
    fw_path = r"C:\Users\CNC\Documents\PDM_Project\pdm_firmware.bin"
    if not os.path.exists(fw_path):
        print(f"Firmware not found: {fw_path}")
        return
    
    with open(fw_path, 'rb') as f:
        fw = f.read()
    
    # MC68HC908GZ60 MSCAN registers are at 0x0040-0x006F
    # The firmware loads at 0x8000, so we can look for code that accesses these
    
    # Look for patterns that reference CAN registers
    # In HC08, direct addressing is used for $00-$FF
    # MSCAN registers:
    mscan_regs = {
        0x40: "CANCTL0",   # Control 0
        0x41: "CANCTL1",   # Control 1
        0x42: "CANBTR0",   # Bus Timing 0
        0x43: "CANBTR1",   # Bus Timing 1
        0x44: "CANRFLG",   # Receive Flag
        0x45: "CANRIER",   # Receive Interrupt Enable
        0x46: "CANTFLG",   # Transmit Flag
        0x47: "CANTIER",   # Transmit Interrupt Enable
        0x48: "CANTARQ",   # Transmit Abort Request
        0x49: "CANTAAK",   # Transmit Abort Acknowledge
        0x4A: "CANTBSEL",  # Transmit Buffer Select
        0x4B: "CANIDAC",   # Identifier Acceptance Control
        0x50: "CANIDAR0",  # ID Acceptance Reg 0
        0x51: "CANIDAR1",
        0x52: "CANIDAR2",
        0x53: "CANIDAR3",
        0x54: "CANIDMR0",  # ID Mask Reg 0
        0x55: "CANIDMR1",
        0x56: "CANIDMR2",
        0x57: "CANIDMR3",
        0x58: "CANIDAR4",
        0x59: "CANIDAR5",
        0x5A: "CANIDAR6",
        0x5B: "CANIDAR7",
        0x5C: "CANIDMR4",
        0x5D: "CANIDMR5",
        0x5E: "CANIDMR6",
        0x5F: "CANIDMR7",
        0x60: "CANRXFG",   # Receive Foreground Buffer (16 bytes)
        0x70: "CANTXFG",   # Transmit Foreground Buffer (16 bytes)
    }
    
    # Search for CAN ID values in firmware
    print("\n--- Searching for CAN ID constants in firmware ---")
    
    # Look for common CAN IDs
    target_ids = [
        (0x118, "CAN Input Base (280)"),
        (0x500, "CAN Output Base (1280)"),
        (0x7E0, "Diagnostic Request"),
        (0x7E8, "Diagnostic Response"),
        (0x600, "Rebased Request Base"),
        (0x608, "Rebased Response Base"),
    ]
    
    for can_id, desc in target_ids:
        # Search for big-endian (network order) and little-endian
        be_bytes = struct.pack('>H', can_id)
        le_bytes = struct.pack('<H', can_id)
        
        be_pos = [i for i in range(len(fw)-1) if fw[i:i+2] == be_bytes]
        le_pos = [i for i in range(len(fw)-1) if fw[i:i+2] == le_bytes]
        
        if be_pos or le_pos:
            print(f"  0x{can_id:03X} ({desc}):")
            if be_pos:
                addrs = [f"0x{0x8000+p:04X}" for p in be_pos[:5]]
                print(f"    Big-endian at: {', '.join(addrs)}")
            if le_pos:
                addrs = [f"0x{0x8000+p:04X}" for p in le_pos[:5]]
                print(f"    Little-endian at: {', '.join(addrs)}")

def analyze_pdm_manager():
    """Extract protocol info from PDM Manager"""
    print("\n" + "="*70)
    print("PDM MANAGER PROTOCOL ANALYSIS")
    print("="*70)
    
    exe_path = r"C:\Users\CNC\Documents\PDM_Project\MoTeC\PDM Manager\1.9\PDM Manager.exe"
    if not os.path.exists(exe_path):
        print(f"PDM Manager not found: {exe_path}")
        return
    
    with open(exe_path, 'rb') as f:
        data = f.read()
    
    # Extract all printable strings
    strings = re.findall(b'[\x20-\x7e]{4,}', data)
    str_list = [s.decode('ascii', errors='ignore') for s in strings]
    
    # Look for format strings that reveal protocol structure
    print("\n--- Format strings (reveal message structure) ---")
    for s in str_list:
        if '%' in s and any(x in s.lower() for x in ['can', 'msg', 'pkt', 'cmd', 'req', 'res', 'id']):
            if len(s) < 100:
                print(f"  {s}")
    
    # Look for error messages that reveal protocol
    print("\n--- Error messages (protocol hints) ---")
    error_keywords = ['error', 'fail', 'invalid', 'timeout', 'cannot']
    for s in str_list:
        for kw in error_keywords:
            if kw in s.lower() and any(x in s.lower() for x in ['can', 'msg', 'comm', 'connect']):
                if len(s) < 100:
                    print(f"  {s}")
                    break

def analyze_gateway_protocol():
    """Analyze the gateway communication protocol"""
    print("\n" + "="*70)
    print("GATEWAY PROTOCOL (UDP/mDNS)")
    print("="*70)
    
    disc_path = r"C:\Users\CNC\Documents\PDM_Project\MoTeC\Discovery\1.0\MoTeC.Discovery.exe"
    if not os.path.exists(disc_path):
        print(f"Discovery not found")
        return
        
    with open(disc_path, 'rb') as f:
        data = f.read()
    
    strings = re.findall(b'[\x20-\x7e]{4,}', data)
    str_list = [s.decode('ascii', errors='ignore') for s in strings]
    
    # Find gateway command strings
    print("\n--- Gateway Commands ---")
    for s in str_list:
        if s.startswith('gw_'):
            print(f"  {s}")
    
    # Find packet structure hints
    print("\n--- Packet/Protocol Structure ---")
    for s in str_list:
        if any(x in s for x in ['hdr', 'header', 'payload', 'length', 'size', 'byte']):
            if len(s) < 60 and not '@@' in s:
                print(f"  {s}")

def summarize_protocol():
    """Print a summary of what we know about the protocol"""
    print("\n" + "="*70)
    print("PROTOCOL SUMMARY")
    print("="*70)
    
    print("""
## PDM Communication Architecture

### 1. Runtime CAN (PDM <-> ECU)
   - PDM receives data from ECU on CAN IDs 0x118-0x11B (280-283)
   - PDM transmits status on CAN IDs 0x500+ (1280+)
   - Standard 8-byte CAN frames
   - User-configurable via .pdm XML files

### 2. PC Communication (PDM Manager <-> Gateway <-> PDM)

   PC -> Gateway: UDP over network
   - Gateway discovered via mDNS: _motec-gw-can._udp
   - TXT record contains: reqbase, resbase, canif, cankbaud
   
   Gateway -> PDM: CAN
   - Request CAN ID: 0x7E0 (or rebased)
   - Response CAN ID: 0x7E8 (or rebased)

### 3. Command Protocol (ISO-TP style)
   
   Operations are sent as CAN frames to request ID:
   - OpGetSerialNum: Get device serial number
   - OpGetVersion: Get firmware version
   - OpUnlockConfig: Prepare for config write
   - OpWriteConfig: Send configuration data
   - OpRelock: Lock after config write
   - OpReset: Reset device
   
### 4. Gateway Protocol (UDP packets)
   
   Commands identified:
   - gw_set: Set parameter
   - gw_examine: Query state
   - gw_pkt: Packet setting
   - gw_overlap: Overlap mode
   - gw_ver: Version
   - gw_name: Device name
   
   The gateway wraps CAN frames in UDP for network transport.

### 5. To Use CANtact Pro

   Option A: Emulate Gateway
   - Advertise _motec-gw-can._udp via mDNS
   - Accept UDP connections
   - Extract CAN frames and send via CANtact
   - Return responses wrapped in UDP
   
   Option B: Direct CAN (bypass PDM Manager)
   - Connect CANtact directly to PDM CAN bus
   - Send commands using request ID 0x7E0
   - Monitor responses on 0x7E8
   - Implement command protocol manually
""")

def main():
    analyze_firmware_can()
    analyze_pdm_manager()
    analyze_gateway_protocol()
    summarize_protocol()

if __name__ == "__main__":
    main()
