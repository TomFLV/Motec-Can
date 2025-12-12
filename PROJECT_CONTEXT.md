# MoTeC PDM Reverse Engineering Project - Context File
# =====================================================
# This file helps quickly resume work on this project.
# Last updated: December 12, 2025

## PROJECT GOAL
Reverse engineer MoTeC PDM (Power Distribution Module) to enable communication
using a CANtact Pro USB-CAN adapter instead of the proprietary MoTeC UTC gateway.

## HARDWARE
- **PDM Unit**: MoTeC PDM (Power Distribution Module)
- **MCU**: MC68HC908GZ60 (Motorola/Freescale 8-bit HC08)
  - 60KB Flash, 2KB RAM
  - Integrated MSCAN controller
  - Runs at ~8MHz (bus clock)
- **Target Interface**: CANtact Pro (USB to CAN adapter)

## KEY FINDINGS

### 1. Device Discovery
The MoTeC software discovers gateways via **mDNS** (Bonjour/Avahi):
- Service type: `_motec-gw-can._udp`
- Alternative: `_motec-11._udp` (device ID 0x11 = PDM)

### 2. mDNS TXT Record Fields
```
txtvers=1
hw=<hardware ID>
ver=<version>
type=<device type>
canif=<CAN interface number>
cankbaud=<CAN baud in kbps>
reqbase=0x<request CAN ID>
resbase=0x<response CAN ID>
```

### 3. USB Device (if using ADR2 direct USB)
- VID: 0x0403 (FTDI)
- PID: 0x6138
- Uses FTDI D2XX API

### 4. CAN IDs

#### Runtime CAN (PDM <-> ECU)
| Purpose | CAN ID | Decimal |
|---------|--------|---------|
| Input Base | 0x118 | 280 |
| Input Msg 1 | 0x119 | 281 |
| Input Msg 2 | 0x11A | 282 |
| Input Msg 3 | 0x11B | 283 |
| Output Base | 0x500 | 1280 |
| Custom Msgs | 0x520+ | 1312+ |

#### PC Communication (Config/Diagnostics)
| Purpose | CAN ID |
|---------|--------|
| Request (PC->PDM) | 0x7E0 |
| Response (PDM->PC) | 0x7E8 |
| Rebased Request | 0x600 + (serial % 16) * 0x10 |
| Rebased Response | 0x608 + (serial % 16) * 0x10 |

### 5. Operation Commands (from PDM Manager.exe)
```
OpGetSerialNum      - Get device serial number
OpGetVersion        - Get firmware version  
OpGetHWId           - Get hardware ID
OpGetHWNum          - Get hardware number
OpGetChannels       - Get channel info
OpUnlockConfig      - Unlock for config write
OpWriteConfig       - Write configuration
OpRelock            - Lock after write
OpReset             - Reset device
OpResetAndStay      - Reset and stay in bootloader
OpSetHalt           - Halt operation
OpClearHalt         - Resume operation
OpUnlockFirmware    - Unlock for firmware update
OpWriteFirmware     - Write firmware
OpGetFirmwareStatus - Check firmware status
OpSetBitrate        - Set CAN baud rate
OpRebase            - Change CAN IDs
OpUnRebase          - Reset to default CAN IDs
```

### 6. Gateway Protocol (UDP)
Gateway commands (gw_* strings found in binary):
- gw_set=%d     - Set parameter
- gw_examine=%d - Query state
- gw_pkt=%d     - Packet size setting
- gw_overlap=%d - Overlap mode
- gw_ver=%d     - Version query
- gw_name=%s    - Name query

## FILES IN PROJECT

### Analysis Scripts
| File | Purpose |
|------|---------|
| srec_to_bin.py | Convert Motorola S-record to binary |
| hc08_disasm.py | Full HC08 instruction set disassembler |
| analyze_pdm.py | Firmware structure analyzer |
| pdm_protocol.py | Protocol documentation |
| find_device_id.py | Search for USB VID/PID |
| extract_can_protocol.py | Extract CAN protocol from binaries |
| cantact_pdm.py | CANtact Pro communication tool |

### Output Files
| File | Purpose |
|------|---------|
| pdm_firmware.bin | Raw firmware binary (20,331 bytes) |
| pdm_disasm.asm | Full firmware disassembly |
| pdm_analysis.txt | Firmware analysis report |
| PDM_PROTOCOL_ANALYSIS.md | Protocol documentation |

### MoTeC Software (in MoTeC/ folder)
- PDM Manager/1.9/PDM Manager.exe - Main application
- PDM Manager/1.9/MoTeC.Discovery.dll - Discovery library
- PDM Manager/1.9/pdm.hex - Firmware in S-record format
- Discovery/1.0/MoTeC.Discovery.exe - Standalone discovery tool

## NEXT STEPS

### Option A: Gateway Emulator (Recommended)
Create a Python script that:
1. Advertises `_motec-gw-can._udp` via mDNS (zeroconf library)
2. Listens for UDP connections from PDM Manager
3. Extracts CAN frames from UDP packets
4. Sends them via CANtact Pro (python-can library)
5. Returns responses wrapped back in UDP

### Option B: Direct CAN Communication
Bypass PDM Manager entirely:
1. Connect CANtact Pro to PDM CAN bus
2. Send commands to 0x7E0
3. Receive responses from 0x7E8
4. Implement protocol manually

## DEPENDENCIES
```
pip install python-can    # CAN communication
pip install zeroconf      # mDNS for gateway emulator
```

## QUICK START COMMANDS
```powershell
# Navigate to project
cd C:\Users\CNC\Documents\PDM_Project

# Run firmware disassembler
python hc08_disasm.py

# Run protocol extractor
python extract_can_protocol.py

# Run CANtact tool (when hardware connected)
python cantact_pdm.py scan COM3
```

## FIRMWARE NOTES
- Firmware loads at address 0x8000
- Size: 20,331 bytes (0x4F6B)
- End address: 0xCF6A
- Entry point: 0xFFFF (handled by bootloader)
- CAN input base 0x118 found at firmware offset 0x04C9, 0x1455
- CAN output base 0x500 found at firmware offset 0x01F9, 0x0200

## REGISTRY/CONFIG KEYS (Windows)
- MoTeC.PDM.RebaseReqId - Custom request CAN ID
- MoTeC.PDM.RebaseResId - Custom response CAN ID
- AllowRemoteGateways - Allow network gateways
