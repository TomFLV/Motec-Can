#!/usr/bin/env python3
"""
PDM Firmware Analyzer - MC68HC908GZ60
Analyze structure and functionality of MoTeC PDM firmware
"""

import re
from collections import defaultdict

# MC68HC908GZ60 I/O Registers
IO_REGS = {
    0x00: "PORTA", 0x01: "PORTB", 0x02: "PORTC", 0x03: "PORTD",
    0x04: "DDRA", 0x05: "DDRB", 0x06: "DDRC", 0x07: "DDRD",
    0x08: "PORTE", 0x09: "PORTF", 0x0A: "PORTG",
    0x0C: "DDRE", 0x0D: "DDRF", 0x0E: "DDRG",
    0x10: "PTAPUE", 0x11: "PTBPUE", 0x12: "PTCPUE", 0x13: "PTDPUE",
    0x14: "PTEPUE", 0x15: "PTFPUE", 0x16: "PTGPUE",
    # SCI (Serial)
    0x18: "SCC1", 0x19: "SCC2", 0x1A: "SCC3", 0x1B: "SCS1",
    0x1C: "SCS2", 0x1D: "SCDR", 0x1E: "SCBR",
    # SPI
    0x20: "SPCR", 0x21: "SPSCR", 0x22: "SPDR",
    # Timebase
    0x24: "TBCR", 0x25: "TBDR",
    # Timer 1
    0x30: "T1SC", 0x31: "T1CNTH", 0x32: "T1CNTL",
    0x33: "T1MODH", 0x34: "T1MODL",
    0x35: "T1SC0", 0x36: "T1CH0H", 0x37: "T1CH0L",
    0x38: "T1SC1", 0x39: "T1CH1H", 0x3A: "T1CH1L",
    # Timer 2
    0x40: "T2SC", 0x41: "T2CNTH", 0x42: "T2CNTL",
    0x43: "T2MODH", 0x44: "T2MODL",
    0x45: "T2SC0", 0x46: "T2CH0H", 0x47: "T2CH0L",
    0x48: "T2SC1", 0x49: "T2CH1H", 0x4A: "T2CH1L",
    # ADC
    0x50: "ADSCR", 0x51: "ADR",
    # MSCAN
    0x58: "CMCR0", 0x59: "CMCR1", 0x5A: "CBTR0", 0x5B: "CBTR1",
    0x5C: "CRFLG", 0x5D: "CRIER", 0x5E: "CTFLG", 0x5F: "CTIER",
    0x60: "CTARQ", 0x61: "CTAAK", 0x62: "CTBSEL", 0x63: "CIDAC",
    0x64: "CRXERR", 0x65: "CTXERR",
    0x68: "CIDAR0", 0x69: "CIDAR1", 0x6A: "CIDAR2", 0x6B: "CIDAR3",
    0x70: "CIDMR0", 0x71: "CIDMR1", 0x72: "CIDMR2", 0x73: "CIDMR3",
    0x74: "CIDAR4", 0x75: "CIDAR5", 0x76: "CIDAR6", 0x77: "CIDAR7",
    0x78: "CIDMR4", 0x79: "CIDMR5", 0x7A: "CIDMR6", 0x7B: "CIDMR7",
    0x80: "CRXFG",  # RX buffer starts here (16 bytes)
    0x90: "CTXFG",  # TX buffer starts here (16 bytes)
    # Config
    0xFE00: "CONFIG2", 0xFE01: "CONFIG1",
}

def load_binary(filename):
    with open(filename, 'rb') as f:
        return bytearray(f.read())

def find_subroutines(data, base=0x8000):
    """Find all JSR/BSR targets - these are subroutines"""
    subs = set()
    pc = 0
    
    while pc < len(data):
        op = data[pc]
        
        # JSR direct ($BD)
        if op == 0xBD and pc + 1 < len(data):
            target = data[pc + 1]
            subs.add(target)
            pc += 2
        # JSR extended ($CD)
        elif op == 0xCD and pc + 2 < len(data):
            target = (data[pc + 1] << 8) | data[pc + 2]
            subs.add(target)
            pc += 3
        # BSR relative ($AD)
        elif op == 0xAD and pc + 1 < len(data):
            rel = data[pc + 1]
            if rel > 127:
                rel -= 256
            target = base + pc + 2 + rel
            subs.add(target)
            pc += 2
        else:
            pc += 1
    
    return sorted(subs)

def find_io_accesses(data, base=0x8000):
    """Find I/O register accesses"""
    io_reads = defaultdict(list)
    io_writes = defaultdict(list)
    pc = 0
    
    while pc < len(data):
        op = data[pc]
        addr = base + pc
        
        # LDA direct ($B6) - read
        if op == 0xB6 and pc + 1 < len(data):
            reg = data[pc + 1]
            if reg in IO_REGS:
                io_reads[reg].append(addr)
            pc += 2
        # STA direct ($B7) - write
        elif op == 0xB7 and pc + 1 < len(data):
            reg = data[pc + 1]
            if reg in IO_REGS:
                io_writes[reg].append(addr)
            pc += 2
        # LDX direct ($BE) - read
        elif op == 0xBE and pc + 1 < len(data):
            reg = data[pc + 1]
            if reg in IO_REGS:
                io_reads[reg].append(addr)
            pc += 2
        # STX direct ($BF) - write
        elif op == 0xBF and pc + 1 < len(data):
            reg = data[pc + 1]
            if reg in IO_REGS:
                io_writes[reg].append(addr)
            pc += 2
        # BSET/BCLR ($10-$1F) - write
        elif 0x10 <= op <= 0x1F and pc + 1 < len(data):
            reg = data[pc + 1]
            if reg in IO_REGS:
                io_writes[reg].append(addr)
            pc += 2
        # BRSET/BRCLR ($00-$0F) - read
        elif 0x00 <= op <= 0x0F and pc + 2 < len(data):
            reg = data[pc + 1]
            if reg in IO_REGS:
                io_reads[reg].append(addr)
            pc += 3
        # LDA/STA extended for CONFIG registers
        elif op == 0xC6 and pc + 2 < len(data):  # LDA ext
            ext = (data[pc + 1] << 8) | data[pc + 2]
            if ext in IO_REGS:
                io_reads[ext].append(addr)
            pc += 3
        elif op == 0xC7 and pc + 2 < len(data):  # STA ext
            ext = (data[pc + 1] << 8) | data[pc + 2]
            if ext in IO_REGS:
                io_writes[ext].append(addr)
            pc += 3
        else:
            pc += 1
    
    return io_reads, io_writes

def find_ram_usage(data, base=0x8000):
    """Find RAM variable usage patterns"""
    ram_writes = defaultdict(int)
    ram_reads = defaultdict(int)
    pc = 0
    
    while pc < len(data):
        op = data[pc]
        
        # Extended addressing ($C0-$CF, $D0-$DF for indexed)
        if 0xC0 <= op <= 0xCF and op not in [0xCC, 0xCD] and pc + 2 < len(data):
            ext = (data[pc + 1] << 8) | data[pc + 2]
            if 0x0040 <= ext <= 0x083F:  # RAM range
                if op == 0xC7:  # STA
                    ram_writes[ext] += 1
                else:
                    ram_reads[ext] += 1
            pc += 3
        else:
            pc += 1
    
    return ram_reads, ram_writes

def find_strings(data, base=0x8000, min_len=4):
    """Find potential ASCII strings in firmware"""
    strings = []
    i = 0
    while i < len(data):
        if 0x20 <= data[i] <= 0x7E:
            start = i
            while i < len(data) and 0x20 <= data[i] <= 0x7E:
                i += 1
            if i - start >= min_len:
                s = bytes(data[start:i]).decode('ascii')
                strings.append((base + start, s))
        i += 1
    return strings

def analyze_main_loop(data, base=0x8000):
    """Try to identify main loop structure"""
    # Look for backwards branches (loops)
    loops = []
    pc = 0
    
    while pc < len(data):
        op = data[pc]
        # Branch instructions
        if op in [0x20, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 
                  0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x90, 0x91, 0x92, 0x93]:
            if pc + 1 < len(data):
                rel = data[pc + 1]
                if rel > 127:
                    rel -= 256
                target = base + pc + 2 + rel
                if rel < 0:  # Backwards branch
                    loops.append((base + pc, target, -rel))
            pc += 2
        else:
            pc += 1
    
    return loops

def main():
    bin_file = r"C:\Users\CNC\Documents\PDM_Project\pdm_firmware.bin"
    data = load_binary(bin_file)
    base = 0x8000
    
    print("=" * 70)
    print("PDM FIRMWARE ANALYSIS - MC68HC908GZ60")
    print("=" * 70)
    print(f"\nFirmware size: {len(data)} bytes (0x{len(data):04X})")
    print(f"Address range: 0x{base:04X} - 0x{base + len(data) - 1:04X}")
    
    # Find subroutines
    print("\n" + "=" * 70)
    print("SUBROUTINES (JSR/BSR targets)")
    print("=" * 70)
    subs = find_subroutines(data, base)
    print(f"Found {len(subs)} subroutine entry points:")
    
    # Group by region
    regions = {
        "0x8000-0x8FFF (Main code)": [],
        "0x9000-0x9FFF": [],
        "0xA000-0xAFFF": [],
        "0xB000-0xBFFF": [],
        "0xC000-0xCFFF": [],
    }
    for s in subs:
        if 0x8000 <= s < 0x9000:
            regions["0x8000-0x8FFF (Main code)"].append(s)
        elif 0x9000 <= s < 0xA000:
            regions["0x9000-0x9FFF"].append(s)
        elif 0xA000 <= s < 0xB000:
            regions["0xA000-0xAFFF"].append(s)
        elif 0xB000 <= s < 0xC000:
            regions["0xB000-0xBFFF"].append(s)
        elif 0xC000 <= s < 0xD000:
            regions["0xC000-0xCFFF"].append(s)
    
    for region, addrs in regions.items():
        if addrs:
            print(f"\n  {region}: {len(addrs)} functions")
            for a in addrs[:10]:
                print(f"    sub_{a:04X}")
            if len(addrs) > 10:
                print(f"    ... and {len(addrs)-10} more")
    
    # I/O Analysis
    print("\n" + "=" * 70)
    print("I/O REGISTER USAGE")
    print("=" * 70)
    io_reads, io_writes = find_io_accesses(data, base)
    
    print("\n  PORT I/O (GPIO):")
    for reg in sorted(set(list(io_reads.keys()) + list(io_writes.keys()))):
        if reg in IO_REGS and IO_REGS[reg].startswith(('PORT', 'DDR', 'PT')):
            name = IO_REGS[reg]
            r = len(io_reads.get(reg, []))
            w = len(io_writes.get(reg, []))
            print(f"    {name:10s} - Read: {r:3d}x, Write: {w:3d}x")
    
    print("\n  TIMER (PWM outputs):")
    for reg in sorted(set(list(io_reads.keys()) + list(io_writes.keys()))):
        if reg in IO_REGS and IO_REGS[reg].startswith('T'):
            name = IO_REGS[reg]
            r = len(io_reads.get(reg, []))
            w = len(io_writes.get(reg, []))
            if r > 0 or w > 0:
                print(f"    {name:10s} - Read: {r:3d}x, Write: {w:3d}x")
    
    print("\n  CAN Controller (MSCAN):")
    can_used = False
    for reg in sorted(set(list(io_reads.keys()) + list(io_writes.keys()))):
        if reg in IO_REGS and IO_REGS[reg].startswith('C'):
            name = IO_REGS[reg]
            r = len(io_reads.get(reg, []))
            w = len(io_writes.get(reg, []))
            if r > 0 or w > 0:
                print(f"    {name:10s} - Read: {r:3d}x, Write: {w:3d}x")
                can_used = True
    if not can_used:
        print("    (CAN accessed via extended addressing)")
    
    print("\n  ADC:")
    for reg in sorted(set(list(io_reads.keys()) + list(io_writes.keys()))):
        if reg in IO_REGS and IO_REGS[reg].startswith('AD'):
            name = IO_REGS[reg]
            r = len(io_reads.get(reg, []))
            w = len(io_writes.get(reg, []))
            if r > 0 or w > 0:
                print(f"    {name:10s} - Read: {r:3d}x, Write: {w:3d}x")
    
    print("\n  SPI:")
    for reg in sorted(set(list(io_reads.keys()) + list(io_writes.keys()))):
        if reg in IO_REGS and IO_REGS[reg].startswith('SP'):
            name = IO_REGS[reg]
            r = len(io_reads.get(reg, []))
            w = len(io_writes.get(reg, []))
            if r > 0 or w > 0:
                print(f"    {name:10s} - Read: {r:3d}x, Write: {w:3d}x")
    
    # RAM usage
    print("\n" + "=" * 70)
    print("RAM VARIABLE HOTSPOTS")
    print("=" * 70)
    ram_reads, ram_writes = find_ram_usage(data, base)
    
    # Find most accessed variables
    all_ram = set(ram_reads.keys()) | set(ram_writes.keys())
    by_access = [(addr, ram_reads.get(addr, 0) + ram_writes.get(addr, 0)) for addr in all_ram]
    by_access.sort(key=lambda x: -x[1])
    
    print("\n  Most frequently accessed RAM locations:")
    for addr, count in by_access[:20]:
        r = ram_reads.get(addr, 0)
        w = ram_writes.get(addr, 0)
        print(f"    ${addr:04X}  - Read: {r:3d}x, Write: {w:3d}x  (total: {count})")
    
    # Main loop detection
    print("\n" + "=" * 70)
    print("LOOP STRUCTURES")
    print("=" * 70)
    loops = analyze_main_loop(data, base)
    
    # Find largest backwards jumps (likely main loops)
    big_loops = [l for l in loops if l[2] > 50]  # > 50 bytes back
    big_loops.sort(key=lambda x: -x[2])
    
    print("\n  Large loops (likely main loop or state machines):")
    for branch_addr, target, size in big_loops[:10]:
        print(f"    ${branch_addr:04X} -> ${target:04X} (loops back {size} bytes)")
    
    # Strings
    print("\n" + "=" * 70)
    print("EMBEDDED STRINGS")
    print("=" * 70)
    strings = find_strings(data, base, min_len=4)
    if strings:
        for addr, s in strings[:20]:
            # Filter out likely non-strings
            if not all(c in '0123456789ABCDEFabcdef' for c in s):
                print(f"    ${addr:04X}: \"{s}\"")
    else:
        print("    No ASCII strings found")
    
    # Key addresses summary
    print("\n" + "=" * 70)
    print("FIRMWARE STRUCTURE SUMMARY")
    print("=" * 70)
    print("""
    Based on analysis, this PDM firmware appears to have:
    
    1. INITIALIZATION (0x8000-0x8100):
       - Hardware setup (ports, timers, CAN)
       - Configuration loading
       
    2. MAIN LOOP (around 0x816D based on BRA $816D at 0x81AF):
       - State machine with states 0-3 (see 0x80CF-0x80DD)
       - Watchdog servicing (writes to $FFFF)
       - Input processing
       
    3. OUTPUT CONTROL:
       - PWM via Timer channels for PDM outputs
       - GPIO for discrete outputs
       
    4. CAN COMMUNICATION:
       - Message reception and transmission
       - Likely implements MoTeC CAN protocol
       
    5. KEY RAM VARIABLES:
       - $02FA: Main state variable
       - $02FB-$02FF: Configuration/status
       - $0100-$0110: Communication buffers
       - $0462-$0469: Channel states
""")
    
    # Save detailed analysis
    output_file = r"C:\Users\CNC\Documents\PDM_Project\pdm_analysis.txt"
    with open(output_file, 'w') as f:
        f.write("PDM Firmware Analysis Report\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("SUBROUTINES:\n")
        for s in subs:
            f.write(f"  sub_{s:04X}\n")
        
        f.write("\n\nI/O REGISTER ACCESS LOCATIONS:\n")
        for reg in sorted(io_writes.keys()):
            if reg in IO_REGS:
                f.write(f"\n{IO_REGS[reg]} writes:\n")
                for addr in io_writes[reg]:
                    f.write(f"  ${addr:04X}\n")
        
        f.write("\n\nLOOP LOCATIONS:\n")
        for branch_addr, target, size in loops:
            f.write(f"  ${branch_addr:04X} -> ${target:04X} ({size} bytes)\n")
    
    print(f"\nDetailed analysis saved to: {output_file}")

if __name__ == "__main__":
    main()
