#!/usr/bin/env python3
"""
Convert Motorola S-record file to binary for HC08 disassembly
"""

import sys
import os

def parse_srec(filename):
    """Parse S-record file and return dict of address->data"""
    memory = {}
    start_addr = None
    end_addr = 0
    
    with open(filename, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            if not line.startswith('S'):
                print(f"Warning: Line {line_num} doesn't start with 'S': {line[:20]}...")
                continue
            
            record_type = line[1]
            
            if record_type == '0':
                # Header record
                byte_count = int(line[2:4], 16)
                data_hex = line[8:8+(byte_count-3)*2]
                header = bytes.fromhex(data_hex).decode('ascii', errors='replace')
                print(f"Header: {header}")
                
            elif record_type == '1':
                # Data record with 16-bit address
                byte_count = int(line[2:4], 16)
                address = int(line[4:8], 16)
                data_hex = line[8:8+(byte_count-3)*2]
                data = bytes.fromhex(data_hex)
                
                if start_addr is None or address < start_addr:
                    start_addr = address
                if address + len(data) > end_addr:
                    end_addr = address + len(data)
                
                for i, b in enumerate(data):
                    memory[address + i] = b
                    
            elif record_type == '2':
                # Data record with 24-bit address
                byte_count = int(line[2:4], 16)
                address = int(line[4:10], 16)
                data_hex = line[10:10+(byte_count-4)*2]
                data = bytes.fromhex(data_hex)
                
                if start_addr is None or address < start_addr:
                    start_addr = address
                if address + len(data) > end_addr:
                    end_addr = address + len(data)
                
                for i, b in enumerate(data):
                    memory[address + i] = b
                    
            elif record_type == '9':
                # End record with 16-bit start address
                entry_point = int(line[4:8], 16)
                print(f"Entry point: 0x{entry_point:04X}")
                
            elif record_type == '8':
                # End record with 24-bit start address
                entry_point = int(line[4:10], 16)
                print(f"Entry point: 0x{entry_point:06X}")
                
    return memory, start_addr, end_addr

def save_binary(memory, start_addr, end_addr, output_file):
    """Save memory contents to binary file"""
    size = end_addr - start_addr
    binary = bytearray(size)
    
    # Fill with 0xFF (erased flash)
    for i in range(size):
        binary[i] = 0xFF
    
    # Copy data
    for addr, byte in memory.items():
        offset = addr - start_addr
        if 0 <= offset < size:
            binary[offset] = byte
    
    with open(output_file, 'wb') as f:
        f.write(binary)
    
    return size

def main():
    input_file = r"C:\Users\CNC\Documents\PDM_Project\MoTeC\PDM Manager\1.9\pdm.hex"
    output_file = r"C:\Users\CNC\Documents\PDM_Project\pdm_firmware.bin"
    
    print(f"Parsing: {input_file}")
    memory, start_addr, end_addr = parse_srec(input_file)
    
    print(f"\nMemory range: 0x{start_addr:04X} - 0x{end_addr:04X}")
    print(f"Total size: {end_addr - start_addr} bytes ({(end_addr - start_addr)/1024:.1f} KB)")
    print(f"Data bytes: {len(memory)}")
    
    size = save_binary(memory, start_addr, end_addr, output_file)
    print(f"\nSaved to: {output_file}")
    print(f"Binary size: {size} bytes")
    
    # Also create an IDA Python script for proper setup
    ida_script = r"C:\Users\CNC\Documents\PDM_Project\ida_hc08_setup.py"
    with open(ida_script, 'w') as f:
        f.write(f'''# IDA Python script for HC08 PDM firmware analysis
# Load this after opening the binary

import idc
import idaapi

# MC68HC908GZ60 memory map
# Flash: 0x8000 - 0xFFFF (60KB, but we have less)
# RAM: 0x0040 - 0x083F (2KB)
# Registers: 0x0000 - 0x003F

print("Setting up MC68HC908GZ60 memory regions...")

# Set processor to MC68HC08
# idaapi.set_processor_type("mc8", idaapi.SETPROC_LOADER)

# Important vectors at end of memory (0xFFxx)
vectors = {{
    0xFFDC: "TIMEBASE_VECTOR",
    0xFFDE: "ADC_VECTOR", 
    0xFFE0: "KEYBOARD_VECTOR",
    0xFFE2: "SCITX_VECTOR",
    0xFFE4: "SCIRX_VECTOR",
    0xFFE6: "SCIERR_VECTOR",
    0xFFE8: "SPITX_VECTOR",
    0xFFEA: "SPIRX_VECTOR",
    0xFFEC: "TIM2OVF_VECTOR",
    0xFFEE: "TIM2CH1_VECTOR",
    0xFFF0: "TIM2CH0_VECTOR",
    0xFFF2: "TIM1OVF_VECTOR",
    0xFFF4: "TIM1CH1_VECTOR",
    0xFFF6: "TIM1CH0_VECTOR",
    0xFFF8: "PLL_VECTOR",
    0xFFFA: "IRQ_VECTOR",
    0xFFFC: "SWI_VECTOR",
    0xFFFE: "RESET_VECTOR",
}}

print("HC08 PDM firmware loaded at 0x{start_addr:04X}")
print(f"Size: {end_addr - start_addr} bytes")
''')
    
    print(f"IDA setup script: {ida_script}")
    
    # Print some analysis
    print("\n--- Quick Analysis ---")
    
    # Check reset vector
    if 0xFFFE in memory and 0xFFFF in memory:
        reset_vector = (memory[0xFFFE] << 8) | memory[0xFFFF]
        print(f"Reset vector: 0x{reset_vector:04X}")
    
    # Check IRQ vector
    if 0xFFFA in memory and 0xFFFB in memory:
        irq_vector = (memory[0xFFFA] << 8) | memory[0xFFFB]
        print(f"IRQ vector: 0x{irq_vector:04X}")
    
    # Check SWI vector
    if 0xFFFC in memory and 0xFFFD in memory:
        swi_vector = (memory[0xFFFC] << 8) | memory[0xFFFD]
        print(f"SWI vector: 0x{swi_vector:04X}")

if __name__ == "__main__":
    main()
