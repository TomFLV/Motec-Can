#!/usr/bin/env python3
"""
Search MoTeC binaries for USB device identification info
"""
import re
import struct
import os

def extract_strings(data, min_length=4):
    """Extract all printable ASCII strings from binary data"""
    strings = []
    current = b''
    for byte in data:
        if 0x20 <= byte <= 0x7e:
            current += bytes([byte])
        else:
            if len(current) >= min_length:
                strings.append(current.decode('ascii', errors='ignore'))
            current = b''
    if len(current) >= min_length:
        strings.append(current.decode('ascii', errors='ignore'))
    return strings

def search_file(filepath):
    """Search a binary file for device identification info"""
    print(f"\n{'='*60}")
    print(f"Analyzing: {os.path.basename(filepath)}")
    print(f"{'='*60}")
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    strings = extract_strings(data)
    
    # Look for USB device identification patterns
    print("\n--- FTDI Serial Number Patterns ---")
    for s in strings:
        # MoTeC FTDI serials are typically alphanumeric, 8 chars
        if re.match(r'^[A-Z]{2}\d{6}$', s) or re.match(r'^[A-Z0-9]{8}$', s):
            print(f"  Potential serial: {s}")
    
    print("\n--- Device Description Strings ---")
    for s in strings:
        # FTDI description field (used for device filtering)
        if 'ADR' in s and len(s) < 30 and not '@@' in s:
            print(f"  {s}")
        if 'UTC' in s and len(s) < 30 and not '@@' in s and not 'UTC@@' in s:
            print(f"  {s}")
    
    print("\n--- mDNS Service Types ---")
    for s in strings:
        if s.startswith('_') and '._' in s:
            print(f"  {s}")
    
    print("\n--- TXT Record Fields ---")
    txt_fields = set()
    for s in strings:
        # Look for key=value patterns
        m = re.search(r'([a-z]{2,15})=', s)
        if m:
            txt_fields.add(m.group(1))
    for field in sorted(txt_fields):
        print(f"  {field}=")
    
    # Search for hex values that could be VID/PID
    print("\n--- Potential USB VID/PID (hex search) ---")
    # Look for 0x0403 (FTDI VID) followed by another hex value
    for i in range(len(data) - 4):
        # Little endian: 03 04 XX XX
        if data[i] == 0x03 and data[i+1] == 0x04:
            possible_pid = data[i+2] | (data[i+3] << 8)
            if 0x6000 <= possible_pid <= 0x7000:  # FTDI PIDs
                print(f"  Found at 0x{i:X}: VID=0403, PID={possible_pid:04X}")

def main():
    base_path = r"C:\Users\CNC\Documents\PDM_Project\MoTeC"
    
    files_to_check = [
        os.path.join(base_path, "Discovery", "1.0", "MoTeC.Discovery.exe"),
        os.path.join(base_path, "PDM Manager", "1.9", "MoTeC.Discovery.dll"),
        os.path.join(base_path, "PDM Manager", "1.9", "PDM Manager.exe"),
    ]
    
    for filepath in files_to_check:
        if os.path.exists(filepath):
            search_file(filepath)
        else:
            print(f"File not found: {filepath}")
    
    print("\n" + "="*60)
    print("SUMMARY: Device Identification Method")
    print("="*60)
    print("""
Based on analysis, MoTeC Discovery uses TWO methods to find devices:

1. USB ADR2 Discovery (FTDI D2XX API)
   - Uses FT_CreateDeviceInfoList / FT_GetDeviceInfoList
   - Filters by device Description field (programmed in FTDI EEPROM)
   - The Description likely starts with "MoTeC" or "ADR" or "LDM"
   - VID: 0x0403 (FTDI default)
   - PID: Likely 0x6001 (FT232R) or 0x6010 (FT2232)
   
2. UTC Discovery (mDNS/Network)
   - Service type: _motec-gw-can._udp
   - Looks for MoTeC gateways on the network
   - Gateway announces via mDNS (Avahi/Bonjour)
   
The UTC (network gateway) is what the PDM Manager uses for CAN communication.
The ADR2 is an older USB-direct interface.

To use CANtact Pro, you would need to either:
1. Create a fake mDNS service that emulates the MoTeC gateway
2. Or bypass PDM Manager entirely and talk CAN directly
""")

if __name__ == "__main__":
    main()
