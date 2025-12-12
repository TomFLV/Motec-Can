# MoTeC CAN

Reverse engineering MoTeC PDM (Power Distribution Module) CAN protocol to enable communication using third-party CAN adapters (CANtact Pro) instead of proprietary MoTeC UTC gateway.

## Project Status

- ✅ Firmware extracted and converted to binary
- ✅ HC08 disassembler created
- ✅ CAN protocol partially documented
- ✅ mDNS service discovery understood
- 🔄 Gateway emulator in progress

## Hardware

- **Target**: MoTeC PDM (MC68HC908GZ60 MCU)
- **Interface**: CANtact Pro USB-CAN adapter

## CAN Protocol Summary

| Purpose | CAN ID |
|---------|--------|
| PDM Input Base | 0x118 (280) |
| PDM Output Base | 0x500 (1280) |
| PC Request | 0x7E0 |
| PC Response | 0x7E8 |

## Files

- `hc08_disasm.py` - HC08 disassembler
- `cantact_pdm.py` - CANtact Pro communication tool
- `extract_can_protocol.py` - Protocol extraction
- `PROJECT_CONTEXT.md` - Detailed project notes

## Usage

```bash
# Scan for PDM on CAN bus
python cantact_pdm.py scan COM3

# Monitor PDM status messages
python cantact_pdm.py monitor COM3
```

## License

For educational/research purposes only.
