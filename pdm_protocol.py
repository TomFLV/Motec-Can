#!/usr/bin/env python3
"""
MoTeC PDM Communication Protocol Analysis
Based on PDM Manager.exe and PDM firmware reverse engineering

This documents how the PC software communicates with the PDM hardware unit.
"""

# ============================================================================
# CAN MESSAGE STRUCTURE
# ============================================================================

"""
The PDM uses CAN bus communication at configurable baud rates.
Default CAN rates are typically 500 kbps or 1 Mbps.

MESSAGE ID STRUCTURE:
--------------------
The PDM uses two base addresses:
1. CAN Input Base Address (default 0x118 = 280 decimal)
   - Receives commands from ECU/Dash
   - Messages 0-3 at BaseAddress + 0 to BaseAddress + 3
   
2. CAN Output Base Address (default 0x500 = 1280 decimal)  
   - Transmits status/telemetry data
   - Standard messages at BaseAddress + offset
   - Custom messages at specified addresses (e.g., 1312, 1313, 1314, 1315)

PC COMMUNICATION (via CAN Gateway):
----------------------------------
The PDM Manager uses MoTeC CAN Gateway (_motec-gw-can._udp) for USB-to-CAN.
Protocol wraps CAN messages in UDP/TCP for network transport.
"""

# ============================================================================
# COMMAND OPERATIONS (PC -> PDM)
# ============================================================================

PDM_OPERATIONS = {
    # Device Information
    "OpGetConnectionDescription": "Get device connection info",
    "OpGetCopyright": "Get copyright string",
    "OpGetHWNum": "Get hardware number",
    "OpGetHWId": "Get hardware ID",
    "OpGetSerialNum": "Get serial number (e.g., 11109)",
    "OpGetVersion": "Get firmware version string",
    "OpGetVersionMajor": "Get major version number",
    "OpGetChannels": "Get available channels list",
    "OpGetBitrate": "Get current CAN bitrate",
    
    # Rebase (Change CAN IDs)
    "OpRebase": "Rebase CAN message IDs to new addresses",
    "OpUnRebase": "Reset CAN IDs to default",
    
    # Control
    "OpSetHalt": "Halt PDM operation",
    "OpClearHalt": "Resume PDM operation",
    "OpCheckHalt": "Check if PDM is halted",
    "OpReset": "Reset PDM",
    "OpResetAndStay": "Reset and stay in bootloader",
    "OpClearStay": "Clear stay-in-bootloader flag",
    
    # Verification
    "OpVerifyPDMType": "Verify PDM type (15/16/30/32)",
    "OpVerifyLinkedOutputSupport": "Check linked output support",
    "OpVerifySetPasswordSupport": "Check password protection support",
    
    # Firmware
    "OpGetFirmwareStatus": "Get current firmware status",
    "OpVerifyFirmwareStatus": "Verify firmware is valid",
    "OpGetFirmwareVersionFile": "Get firmware version from file",
    "OpGetFirmwareVersionDevice": "Get firmware version from device",
    "OpWriteFirmware": "Write new firmware to device",
    
    # Security
    "OpGetLockStatus": "Get lock/password status",
    "OpUnlockConfig": "Unlock configuration for editing",
    "OpUnlockFirmware": "Unlock firmware for updating",
    "OpUnlock": "General unlock",
    "OpRelock": "Re-lock device",
    "OpSetAllPasswords": "Set all passwords",
    
    # Configuration
    "OpWriteConfig": "Write configuration to PDM",
    "OpGetConfigStatus": "Get configuration status",
    "OpGetPCData": "Get configuration from PDM to PC",
    
    # Calibration
    "OpWriteCalibration": "Write calibration data",
    "OpReadCalibration": "Read calibration data",
    
    # Testing
    "OpWriteOutputTestControl": "Control outputs for testing",
    "OpWriteTestSignature": "Write test signature",
    "OpReadTestStatus": "Read test results",
}

# ============================================================================
# CAN INPUT MESSAGES (ECU/Dash -> PDM)
# ============================================================================

"""
CAN Input Structure:
- Base Address: configurable (default 0x118 = 280)
- 4 messages (Message 0-3) at consecutive IDs
- Each message has 8 bytes
- Bits are masked to extract specific inputs

Example from Sample PDM15:
  Message 0, Byte 1:
    Bit 0 (Mask 0x01): fuelpump.CANinput
    Bit 1 (Mask 0x02): pitspeed.input
    Bit 2 (Mask 0x04): lights.brakes.CANinput  
    Bit 3 (Mask 0x08): intercooler.spray.CANinput
    Bit 4 (Mask 0x10): Engine.Running
    Bit 5 (Mask 0x20): PDM.Master.reset.CANinput
    Bit 6 (Mask 0x40): lights.flash.CANinput
    Bit 7 (Mask 0x80): gearbox.pump.caninput

Timeout: Each message has configurable timeout (default 1.0s)
         On timeout, the CANinput value goes to 0 (or timeout value)
"""

CAN_INPUT_BASE = 0x118  # 280 decimal - configurable
CAN_INPUT_MESSAGES = {
    0: {"id": CAN_INPUT_BASE + 0, "bytes": 8, "timeout_s": 1.0},
    1: {"id": CAN_INPUT_BASE + 1, "bytes": 8, "timeout_s": 1.0},
    2: {"id": CAN_INPUT_BASE + 2, "bytes": 8, "timeout_s": 1.0},
    3: {"id": CAN_INPUT_BASE + 3, "bytes": 8, "timeout_s": 1.0},
}

# ============================================================================
# CAN OUTPUT MESSAGES (PDM -> ECU/Dash/Logger)
# ============================================================================

"""
Standard Messages (auto-generated by PDM):
- Base Address: configurable (default 0x500 = 1280)
- Messages contain:
  - Input State (digital input states)
  - Output Current (per-channel current measurement)
  - Output Load (estimated load %)
  - Output Voltage (per-channel voltage)
  - Output State (on/off, fault, retry status)
  - Input Voltage (analog input readings)

Custom Messages (user-defined):
- 4 configurable messages (addresses 1312, 1313, 1314, 1315 default)
- Each has 8 bytes with user-selectable channels
"""

CAN_OUTPUT_BASE = 0x500  # 1280 decimal - configurable

STANDARD_MESSAGE_TYPES = {
    "InputState": "Digital input on/off states (bit-packed)",
    "OutputCurrent": "Per-channel current in 0.1A or 0.5A resolution",
    "OutputLoad": "Estimated load percentage 0-100%",
    "OutputVoltage": "Per-channel voltage in 0.1V resolution",
    "OutputState": "Active/Fault/OverCurrent/RetriesDone flags",
    "InputVoltage": "Analog input voltage readings",
}

# ============================================================================
# FIRMWARE DATA STRUCTURE
# ============================================================================

"""
PDM Firmware Memory Map (MC68HC908GZ60):

Flash: 0x8000 - 0xFFFF (but firmware only uses 0x8000 - 0xCF6B)
RAM:   0x0040 - 0x083F (2KB)
I/O:   0x0000 - 0x003F (registers)

Key RAM Variables (from analysis):
  $02FA: Main state variable (0=?, 1=?, 2=?, 3=?)
  $02FB: Timing/config
  $02FC: Timing/config  
  $02FD: Current limit setting
  $02FE: Status flags
  $02FF: Config flags (from FLASH CONFIG1 at $FE01)
  
  $0100-$011F: Communication buffers
  $0462-$0469: Channel enable flags
  $0500-$0510: Channel configuration
  $0544-$0558: Input/output data
  $0554-$055A: Output state registers (heavily written)
  $0581-$0595: Status/measurement data

Interrupt Vectors (not in update file - in bootloader):
  $FFFE: RESET
  $FFFC: SWI
  $FFFA: IRQ
  etc.
"""

# ============================================================================
# CONFIGURATION BINARY FORMAT
# ============================================================================

"""
The XML configuration file (.pdm) is converted to binary for transmission.
Based on the firmware analysis, the binary config structure appears to be:

Header:
  - PDM Type (0=PDM15, 1=PDM16, 2=PDM30, 3=PDM32)
  - Serial Number (16-bit)
  - CAN Input Base Address
  - CAN Output Base Address
  
Per Input Pin (23 pins for PDM15):
  - Operation type
  - Threshold values (high/low)
  - Timing (debounce on/off)
  - Polarity/Invert flags
  
Per Output Pin (15 pins for PDM15):
  - Polarity
  - Condition logic (complex tree structure)
  - Max Current limit
  - Retry settings (count, delay, always)
  
CAN Input Definitions (up to 8):
  - Offset (which byte)
  - Mask (which bit)
  - Operation/transform
  
CAN Output Definitions:
  - Standard message enables
  - Custom message addresses
  - Channel mappings
"""

# ============================================================================
# PROTOCOL SEQUENCE EXAMPLES
# ============================================================================

def example_connect_sequence():
    """
    Typical sequence when PDM Manager connects to a PDM:
    
    1. Scan for CAN Gateways (mDNS: _motec-gw-can._udp)
    2. Connect to gateway, select CAN bus
    3. Scan for PDMs (send broadcast query)
    4. For each PDM found:
       a. OpGetSerialNum - get serial
       b. OpGetVersion - get firmware version
       c. OpGetHWId - get hardware ID
       d. OpVerifyPDMType - confirm PDM type
    5. Select PDM to communicate with
    6. OpGetConfigStatus - check current config
    """
    pass

def example_send_config_sequence():
    """
    Sequence to send configuration to PDM:
    
    1. OpUnlockConfig - unlock for writing
    2. OpSetHalt - halt normal operation
    3. OpWriteConfig - send config data (multiple packets)
    4. OpGetConfigStatus - verify write
    5. OpClearHalt - resume operation
    6. OpRelock - re-lock device
    """
    pass

def example_firmware_update_sequence():
    """
    Sequence to update PDM firmware:
    
    1. OpUnlockFirmware - unlock for firmware update
    2. OpResetAndStay - reset into bootloader mode
    3. OpGetFirmwareStatus - verify ready for update
    4. OpWriteFirmware - send firmware data (S-record parsed, binary sent)
    5. OpVerifyFirmwareStatus - verify firmware written
    6. OpReset - reset into new firmware
    7. OpWriteConfig - re-send configuration (required after firmware update)
    """
    pass

# ============================================================================
# OPERATOR CODES (for condition logic)
# ============================================================================

OPERATORS = {
    0: "PASS",           # Pass through (A)
    1: "NOT",            # Logical NOT (!A)
    2: "GT_CONST",       # A > constant
    3: "GE_CONST",       # A >= constant
    4: "LT_CONST",       # A < constant
    5: "LE_CONST",       # A <= constant
    6: "EQ_CONST",       # A == constant
    7: "NE_CONST",       # A != constant
    8: "AND",            # A AND B (group operator)
    9: "OR",             # A OR B (group operator)
    10: "GT_CHAN",       # A > B (channel)
    11: "GE_CHAN",       # A >= B
    12: "LT_CHAN",       # A < B
    13: "FLASH",         # Flash/blink with TimeOn/TimeOff
    14: "HYSTERESIS",    # Hysteresis with Constant/Constant2
    15: "XOR",           # A XOR B
    16: "NAND",          # !(A AND B)
    17: "RAW_BIT",       # Raw bit extraction (for CAN inputs)
}

if __name__ == "__main__":
    print("MoTeC PDM Communication Protocol Analysis")
    print("=" * 60)
    print("\nKey CAN Message IDs:")
    print(f"  CAN Input Base:  0x{CAN_INPUT_BASE:03X} ({CAN_INPUT_BASE})")
    print(f"  CAN Output Base: 0x{CAN_OUTPUT_BASE:03X} ({CAN_OUTPUT_BASE})")
    
    print("\nPDM Operations (PC -> Device):")
    for op, desc in list(PDM_OPERATIONS.items())[:15]:
        print(f"  {op:30s} : {desc}")
    print(f"  ... and {len(PDM_OPERATIONS)-15} more")
    
    print("\nOperator Codes (for logic conditions):")
    for code, name in OPERATORS.items():
        print(f"  {code:2d}: {name}")
