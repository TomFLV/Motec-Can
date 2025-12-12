# MoTeC PDM Communication Analysis

## Overview

This document summarizes how the **MoTeC PDM Manager** software communicates with **PDM15/16/30/32** hardware units based on reverse engineering of:
- `PDM Manager.exe` (PC software)
- `pdm.hex` firmware (MC68HC908GZ60 microcontroller)
- `.pdm` configuration files (XML format)

---

## Communication Architecture

```
┌─────────────────┐     USB      ┌─────────────────┐     CAN Bus    ┌─────────────────┐
│  PDM Manager    │◄────────────►│  MoTeC CAN      │◄──────────────►│     PDM Unit    │
│  (PC Software)  │              │  Gateway        │                │  (HC08 MCU)     │
└─────────────────┘              └─────────────────┘                └─────────────────┘
                                       │
                                  mDNS Discovery
                               _motec-gw-can._udp
```

---

## CAN Message IDs

### Input Messages (ECU/Dash → PDM)

| Message | Default ID | Description |
|---------|------------|-------------|
| Message 0 | 0x118 (280) | Control inputs byte 0-7 |
| Message 1 | 0x119 (281) | Control inputs byte 0-7 |
| Message 2 | 0x11A (282) | Control inputs byte 0-7 |
| Message 3 | 0x11B (283) | Control inputs byte 0-7 |

**Base address is configurable (stored in config as `BaseAddress`)**

Each message has:
- 8 bytes of data
- Configurable timeout (default 1.0s)
- Individual bit masking for digital inputs

### Output Messages (PDM → ECU/Dash/Logger)

| Type | Default Base | Description |
|------|--------------|-------------|
| Standard Messages | 0x500 (1280) | Auto-generated status |
| Custom Message 0 | 0x520 (1312) | User-defined channels |
| Custom Message 1 | 0x521 (1313) | User-defined channels |
| Custom Message 2 | 0x522 (1314) | User-defined channels |
| Custom Message 3 | 0x523 (1315) | User-defined channels |

**Standard message content:**
- Input State (digital states, bit-packed)
- Output Current (per-channel, 0.1A resolution)
- Output Load (% of max current)
- Output Voltage (per-channel)
- Output State (Active/Fault/OverCurrent flags)
- Input Voltage (analog readings)

---

## PC-to-Device Operations

### Device Discovery
```
OpGetSerialNum          → Get PDM serial number
OpGetVersion            → Get firmware version
OpGetHWId               → Get hardware ID
OpVerifyPDMType         → Confirm PDM type (15/16/30/32)
OpGetChannels           → Get available channels
```

### Configuration Transfer
```
OpUnlockConfig          → Unlock device for config write
OpSetHalt               → Halt normal operation
OpWriteConfig           → Send configuration data
OpGetConfigStatus       → Verify config written
OpGetPCData             → Read config from device
OpClearHalt             → Resume normal operation
OpRelock                → Re-lock device
```

### Firmware Update
```
OpUnlockFirmware        → Unlock for firmware write
OpResetAndStay          → Reset into bootloader
OpGetFirmwareStatus     → Check bootloader ready
OpWriteFirmware         → Send firmware data
OpVerifyFirmwareStatus  → Verify firmware
OpReset                 → Boot new firmware
```

### Testing
```
OpWriteOutputTestControl → Manually control outputs
OpReadTestStatus         → Read test results
```

---

## Configuration File Format (.pdm)

XML structure with these main sections:

### SerialNumber
```xml
<SteppedValue ID="SerialNumber" Value="11109"/>
```

### Input Pins (23 pins on PDM15)
```xml
<InputPin PinIndex="0">
  <Operation>
    <Operator ID="Operator" Value="14"/>  <!-- HYSTERESIS -->
    <SteppedValue ID="Constant" Value="4.15"/>   <!-- High threshold -->
    <SteppedValue ID="Constant2" Value="3.56"/>  <!-- Low threshold -->
    <SteppedValue ID="TimeOn" Value="0.1"/>      <!-- Debounce -->
    <SteppedValue ID="TimeOff" Value="0.1"/>
  </Operation>
  <ChannelReference ID="Output" Value="wipers.switch"/>
</InputPin>
```

### Output Pins (15 pins on PDM15)
```xml
<OutputPin PinIndex="0">
  <Condition ID="Output">
    <ConditionArray>
      <OperationGroup>
        <OperationGroupArray>
          <Operation>
            <ChannelReference ID="LeftInput" Value="ignition.switch"/>
            <Operator ID="Operator" Value="0"/>  <!-- PASS -->
          </Operation>
        </OperationGroupArray>
        <Operator ID="Operator" Value="8"/>  <!-- AND -->
      </OperationGroup>
    </ConditionArray>
    <Operator ID="Operator" Value="9"/>  <!-- OR (overall) -->
  </Condition>
  <SteppedValue ID="MaxCurrent" Value="15"/>
  <SteppedValue ID="RetryDelay" Value="1.0"/>
  <SteppedValue ID="NumRetries" Value="3"/>
</OutputPin>
```

### CAN Inputs
```xml
<CANInputs>
  <CANInput>
    <ChannelReference ID="Output" Value="fuelpump.CANinput"/>
    <SteppedValue ID="Offset" Value="1"/>  <!-- Byte 1 -->
    <SteppedValue ID="Mask" Value="1"/>    <!-- Bit 0 -->
    <Operator ID="Operator" Value="17"/>   <!-- RAW_BIT -->
  </CANInput>
  <SteppedValue ID="BaseAddress" Value="280"/>
  <SteppedValue ID="Message 0 Timeout" Value="1.0"/>
</CANInputs>
```

### CAN Outputs
```xml
<CANOutputs>
  <StandardMessages>
    <SteppedValue ID="BaseAddress" Value="1280"/>
    <Bool ID="InputState" Value="1"/>
    <Bool ID="OutputCurrent" Value="1"/>
    <Bool ID="OutputState" Value="1"/>
  </StandardMessages>
  <CANMessage ID="Message0">
    <SteppedValue ID="Address" Value="1312"/>
    <ChannelReference ID="Channel0" Value="some.channel"/>
  </CANMessage>
</CANOutputs>
```

---

## Operator Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | PASS | Pass input through |
| 1 | NOT | Logical invert |
| 2 | GT_CONST | Greater than constant |
| 3 | GE_CONST | Greater or equal constant |
| 4 | LT_CONST | Less than constant |
| 5 | LE_CONST | Less or equal constant |
| 6 | EQ_CONST | Equal to constant |
| 7 | NE_CONST | Not equal constant |
| 8 | AND | Logical AND (group) |
| 9 | OR | Logical OR (group) |
| 10 | GT_CHAN | Greater than channel |
| 11 | GE_CHAN | Greater or equal channel |
| 12 | LT_CHAN | Less than channel |
| 13 | FLASH | Blink with TimeOn/TimeOff |
| 14 | HYSTERESIS | Hysteresis compare |
| 15 | XOR | Exclusive OR |
| 16 | NAND | NOT AND |
| 17 | RAW_BIT | Raw bit extraction |

---

## Firmware Memory Map (MC68HC908GZ60)

| Address Range | Size | Description |
|---------------|------|-------------|
| 0x0000-0x003F | 64B | I/O Registers |
| 0x0040-0x083F | 2KB | RAM |
| 0x8000-0xCF6B | ~20KB | Application Code |
| 0xFE00-0xFE01 | 2B | Configuration |
| 0xFFDC-0xFFFF | 36B | Interrupt Vectors (bootloader) |

### Key RAM Variables
| Address | Purpose |
|---------|---------|
| $02FA | Main state machine (0-3) |
| $02FB-$02FF | Configuration/status |
| $0100-$011F | Communication buffers |
| $0462-$0469 | Channel enable flags |
| $0554-$055A | Output state data |

---

## PDM Types

| Value | Type | Outputs | Inputs |
|-------|------|---------|--------|
| 0 | PDM15 | 15 | 23 |
| 1 | PDM16 | 16 | 24 |
| 2 | PDM30 | 30 | 23 |
| 3 | PDM32 | 32 | 24 |

---

## Files Generated

| File | Description |
|------|-------------|
| `pdm_firmware.bin` | Binary firmware (20,331 bytes) |
| `pdm_disasm.asm` | Full HC08 disassembly |
| `pdm_analysis.txt` | Detailed analysis report |
| `pdm_protocol.py` | Protocol documentation code |
| `hc08_disasm.py` | HC08 disassembler tool |
| `analyze_pdm.py` | Firmware analyzer tool |
