#!/usr/bin/env python3
"""
HC08 Disassembler for PDM firmware analysis
MC68HC908GZ60 instruction set
"""

import sys

# HC08 Instruction Set
# Format: opcode -> (mnemonic, addressing_mode, size, cycles)
# Addressing modes: INH=inherent, IMM=immediate, DIR=direct, EXT=extended, 
# IX=indexed, IX1=indexed 1-byte offset, IX2=indexed 2-byte offset,
# SP1=stack pointer 1-byte, SP2=stack pointer 2-byte, REL=relative

HC08_OPCODES = {
    # Branch instructions
    0x20: ("BRA", "REL", 2), 0x21: ("BRN", "REL", 2),
    0x22: ("BHI", "REL", 2), 0x23: ("BLS", "REL", 2),
    0x24: ("BCC", "REL", 2), 0x25: ("BCS", "REL", 2),
    0x26: ("BNE", "REL", 2), 0x27: ("BEQ", "REL", 2),
    0x28: ("BHCC", "REL", 2), 0x29: ("BHCS", "REL", 2),
    0x2A: ("BPL", "REL", 2), 0x2B: ("BMI", "REL", 2),
    0x2C: ("BMC", "REL", 2), 0x2D: ("BMS", "REL", 2),
    0x2E: ("BIL", "REL", 2), 0x2F: ("BIH", "REL", 2),
    
    # Direct addressing
    0x30: ("NEG", "DIR", 2), 0x33: ("COM", "DIR", 2),
    0x34: ("LSR", "DIR", 2), 0x36: ("ROR", "DIR", 2),
    0x37: ("ASR", "DIR", 2), 0x38: ("LSL", "DIR", 2),
    0x39: ("ROL", "DIR", 2), 0x3A: ("DEC", "DIR", 2),
    0x3C: ("INC", "DIR", 2), 0x3D: ("TST", "DIR", 2),
    0x3F: ("CLR", "DIR", 2),
    
    # Inherent
    0x40: ("NEGA", "INH", 1), 0x41: ("CBEQA", "IMM_REL", 3),
    0x42: ("MUL", "INH", 1), 0x43: ("COMA", "INH", 1),
    0x44: ("LSRA", "INH", 1), 0x46: ("RORA", "INH", 1),
    0x47: ("ASRA", "INH", 1), 0x48: ("LSLA", "INH", 1),
    0x49: ("ROLA", "INH", 1), 0x4A: ("DECA", "INH", 1),
    0x4B: ("DBNZA", "REL", 2), 0x4C: ("INCA", "INH", 1),
    0x4D: ("TSTA", "INH", 1), 0x4F: ("CLRA", "INH", 1),
    
    0x50: ("NEGX", "INH", 1), 0x51: ("CBEQX", "IMM_REL", 3),
    0x52: ("DIV", "INH", 1), 0x53: ("COMX", "INH", 1),
    0x54: ("LSRX", "INH", 1), 0x56: ("RORX", "INH", 1),
    0x57: ("ASRX", "INH", 1), 0x58: ("LSLX", "INH", 1),
    0x59: ("ROLX", "INH", 1), 0x5A: ("DECX", "INH", 1),
    0x5B: ("DBNZX", "REL", 2), 0x5C: ("INCX", "INH", 1),
    0x5D: ("TSTX", "INH", 1), 0x5F: ("CLRX", "INH", 1),
    
    # Indexed no offset
    0x60: ("NEG", "IX", 1), 0x61: ("CBEQ", "IX_REL", 2),
    0x63: ("COM", "IX", 1), 0x64: ("LSR", "IX", 1),
    0x66: ("ROR", "IX", 1), 0x67: ("ASR", "IX", 1),
    0x68: ("LSL", "IX", 1), 0x69: ("ROL", "IX", 1),
    0x6A: ("DEC", "IX", 1), 0x6B: ("DBNZ", "IX_REL", 2),
    0x6C: ("INC", "IX", 1), 0x6D: ("TST", "IX", 1),
    0x6F: ("CLR", "IX", 1),
    
    # Indexed 1-byte offset
    0x70: ("NEG", "IX1", 2), 0x71: ("CBEQ", "IX1_REL", 3),
    0x73: ("COM", "IX1", 2), 0x74: ("LSR", "IX1", 2),
    0x76: ("ROR", "IX1", 2), 0x77: ("ASR", "IX1", 2),
    0x78: ("LSL", "IX1", 2), 0x79: ("ROL", "IX1", 2),
    0x7A: ("DEC", "IX1", 2), 0x7B: ("DBNZ", "IX1_REL", 3),
    0x7C: ("INC", "IX1", 2), 0x7D: ("TST", "IX1", 2),
    0x7F: ("CLR", "IX1", 2),
    
    # Stack operations & misc
    0x80: ("RTI", "INH", 1), 0x81: ("RTS", "INH", 1),
    0x83: ("SWI", "INH", 1), 0x84: ("TAP", "INH", 1),
    0x85: ("TPA", "INH", 1), 0x86: ("PULA", "INH", 1),
    0x87: ("PSHA", "INH", 1), 0x88: ("PULX", "INH", 1),
    0x89: ("PSHX", "INH", 1), 0x8A: ("PULH", "INH", 1),
    0x8B: ("PSHH", "INH", 1), 0x8C: ("CLRH", "INH", 1),
    0x8E: ("STOP", "INH", 1), 0x8F: ("WAIT", "INH", 1),
    
    0x90: ("BGE", "REL", 2), 0x91: ("BLT", "REL", 2),
    0x92: ("BGT", "REL", 2), 0x93: ("BLE", "REL", 2),
    0x94: ("TXS", "INH", 1), 0x95: ("TSX", "INH", 1),
    0x97: ("TAX", "INH", 1), 0x98: ("CLC", "INH", 1),
    0x99: ("SEC", "INH", 1), 0x9A: ("CLI", "INH", 1),
    0x9B: ("SEI", "INH", 1), 0x9C: ("RSP", "INH", 1),
    0x9D: ("NOP", "INH", 1), 0x9F: ("TXA", "INH", 1),
    
    # Load/Store A - immediate and direct
    0xA0: ("SUB", "IMM", 2), 0xA1: ("CMP", "IMM", 2),
    0xA2: ("SBC", "IMM", 2), 0xA3: ("CPX", "IMM", 2),
    0xA4: ("AND", "IMM", 2), 0xA5: ("BIT", "IMM", 2),
    0xA6: ("LDA", "IMM", 2), 0xA8: ("EOR", "IMM", 2),
    0xA9: ("ADC", "IMM", 2), 0xAA: ("ORA", "IMM", 2),
    0xAB: ("ADD", "IMM", 2), 0xAD: ("BSR", "REL", 2),
    0xAE: ("LDX", "IMM", 2), 0xAF: ("AIX", "IMM", 2),
    
    0xB0: ("SUB", "DIR", 2), 0xB1: ("CMP", "DIR", 2),
    0xB2: ("SBC", "DIR", 2), 0xB3: ("CPX", "DIR", 2),
    0xB4: ("AND", "DIR", 2), 0xB5: ("BIT", "DIR", 2),
    0xB6: ("LDA", "DIR", 2), 0xB7: ("STA", "DIR", 2),
    0xB8: ("EOR", "DIR", 2), 0xB9: ("ADC", "DIR", 2),
    0xBA: ("ORA", "DIR", 2), 0xBB: ("ADD", "DIR", 2),
    0xBC: ("JMP", "DIR", 2), 0xBD: ("JSR", "DIR", 2),
    0xBE: ("LDX", "DIR", 2), 0xBF: ("STX", "DIR", 2),
    
    # Extended addressing
    0xC0: ("SUB", "EXT", 3), 0xC1: ("CMP", "EXT", 3),
    0xC2: ("SBC", "EXT", 3), 0xC3: ("CPX", "EXT", 3),
    0xC4: ("AND", "EXT", 3), 0xC5: ("BIT", "EXT", 3),
    0xC6: ("LDA", "EXT", 3), 0xC7: ("STA", "EXT", 3),
    0xC8: ("EOR", "EXT", 3), 0xC9: ("ADC", "EXT", 3),
    0xCA: ("ORA", "EXT", 3), 0xCB: ("ADD", "EXT", 3),
    0xCC: ("JMP", "EXT", 3), 0xCD: ("JSR", "EXT", 3),
    0xCE: ("LDX", "EXT", 3), 0xCF: ("STX", "EXT", 3),
    
    # Indexed 2-byte offset
    0xD0: ("SUB", "IX2", 3), 0xD1: ("CMP", "IX2", 3),
    0xD2: ("SBC", "IX2", 3), 0xD3: ("CPX", "IX2", 3),
    0xD4: ("AND", "IX2", 3), 0xD5: ("BIT", "IX2", 3),
    0xD6: ("LDA", "IX2", 3), 0xD7: ("STA", "IX2", 3),
    0xD8: ("EOR", "IX2", 3), 0xD9: ("ADC", "IX2", 3),
    0xDA: ("ORA", "IX2", 3), 0xDB: ("ADD", "IX2", 3),
    0xDC: ("JMP", "IX2", 3), 0xDD: ("JSR", "IX2", 3),
    0xDE: ("LDX", "IX2", 3), 0xDF: ("STX", "IX2", 3),
    
    # Indexed 1-byte offset
    0xE0: ("SUB", "IX1", 2), 0xE1: ("CMP", "IX1", 2),
    0xE2: ("SBC", "IX1", 2), 0xE3: ("CPX", "IX1", 2),
    0xE4: ("AND", "IX1", 2), 0xE5: ("BIT", "IX1", 2),
    0xE6: ("LDA", "IX1", 2), 0xE7: ("STA", "IX1", 2),
    0xE8: ("EOR", "IX1", 2), 0xE9: ("ADC", "IX1", 2),
    0xEA: ("ORA", "IX1", 2), 0xEB: ("ADD", "IX1", 2),
    0xEC: ("JMP", "IX1", 2), 0xED: ("JSR", "IX1", 2),
    0xEE: ("LDX", "IX1", 2), 0xEF: ("STX", "IX1", 2),
    
    # Indexed no offset
    0xF0: ("SUB", "IX", 1), 0xF1: ("CMP", "IX", 1),
    0xF2: ("SBC", "IX", 1), 0xF3: ("CPX", "IX", 1),
    0xF4: ("AND", "IX", 1), 0xF5: ("BIT", "IX", 1),
    0xF6: ("LDA", "IX", 1), 0xF7: ("STA", "IX", 1),
    0xF8: ("EOR", "IX", 1), 0xF9: ("ADC", "IX", 1),
    0xFA: ("ORA", "IX", 1), 0xFB: ("ADD", "IX", 1),
    0xFC: ("JMP", "IX", 1), 0xFD: ("JSR", "IX", 1),
    0xFE: ("LDX", "IX", 1), 0xFF: ("STX", "IX", 1),
}

# Bit manipulation (0x00-0x1F)
for i in range(8):
    HC08_OPCODES[0x00 + i*2] = (f"BRSET{i}", "DIR_REL", 3)
    HC08_OPCODES[0x01 + i*2] = (f"BRCLR{i}", "DIR_REL", 3)
    HC08_OPCODES[0x10 + i*2] = (f"BSET{i}", "DIR", 2)
    HC08_OPCODES[0x11 + i*2] = (f"BCLR{i}", "DIR", 2)

# 0x9E prefix - SP indexed
HC08_9E_OPCODES = {
    0x60: ("NEG", "SP1", 2), 0x63: ("COM", "SP1", 2),
    0x64: ("LSR", "SP1", 2), 0x66: ("ROR", "SP1", 2),
    0x67: ("ASR", "SP1", 2), 0x68: ("LSL", "SP1", 2),
    0x69: ("ROL", "SP1", 2), 0x6A: ("DEC", "SP1", 2),
    0x6B: ("DBNZ", "SP1_REL", 3), 0x6C: ("INC", "SP1", 2),
    0x6D: ("TST", "SP1", 2), 0x6F: ("CLR", "SP1", 2),
    
    0xD0: ("SUB", "SP2", 3), 0xD1: ("CMP", "SP2", 3),
    0xD2: ("SBC", "SP2", 3), 0xD3: ("CPX", "SP2", 3),
    0xD4: ("AND", "SP2", 3), 0xD5: ("BIT", "SP2", 3),
    0xD6: ("LDA", "SP2", 3), 0xD7: ("STA", "SP2", 3),
    0xD8: ("EOR", "SP2", 3), 0xD9: ("ADC", "SP2", 3),
    0xDA: ("ORA", "SP2", 3), 0xDB: ("ADD", "SP2", 3),
    
    0xE0: ("SUB", "SP1", 2), 0xE1: ("CMP", "SP1", 2),
    0xE2: ("SBC", "SP1", 2), 0xE3: ("CPX", "SP1", 2),
    0xE4: ("AND", "SP1", 2), 0xE5: ("BIT", "SP1", 2),
    0xE6: ("LDA", "SP1", 2), 0xE7: ("STA", "SP1", 2),
    0xE8: ("EOR", "SP1", 2), 0xE9: ("ADC", "SP1", 2),
    0xEA: ("ORA", "SP1", 2), 0xEB: ("ADD", "SP1", 2),
}

# MC68HC908GZ60 I/O Register names
IO_REGS = {
    0x00: "PORTA", 0x01: "PORTB", 0x02: "PORTC", 0x03: "PORTD",
    0x04: "DDRA", 0x05: "DDRB", 0x06: "DDRC", 0x07: "DDRD",
    0x08: "PORTE", 0x09: "PORTF", 0x0A: "PORTG",
    0x0C: "DDRE", 0x0D: "DDRF", 0x0E: "DDRG",
    0x10: "PTAPUE", 0x11: "PTBPUE", 0x12: "PTCPUE", 0x13: "PTDPUE",
    0x1A: "SCI1S1", 0x1B: "SCI1S2", 0x1C: "SCI1C1", 0x1D: "SCI1C2",
    0x1E: "SCI1C3", 0x1F: "SCI1D",
    0x20: "SPIC1", 0x21: "SPIC2", 0x22: "SPIBR", 0x23: "SPIS",
    0x25: "SPID",
    0x30: "T1SC", 0x31: "T1CNTH", 0x32: "T1CNTL",
    0x33: "T1MODH", 0x34: "T1MODL",
    0x35: "T1SC0", 0x36: "T1CH0H", 0x37: "T1CH0L",
    0x38: "T1SC1", 0x39: "T1CH1H", 0x3A: "T1CH1L",
    0x40: "ADCSC1", 0x41: "ADCSC2", 0x42: "ADCRH", 0x43: "ADCRL",
    0x48: "CANCTL0", 0x49: "CANCTL1", 0x4A: "CANBTR0", 0x4B: "CANBTR1",
    0x4C: "CANRFLG", 0x4D: "CANRIER", 0x4E: "CANTFLG", 0x4F: "CANTIER",
}

def get_reg_name(addr):
    if addr in IO_REGS:
        return IO_REGS[addr]
    elif addr < 0x40:
        return f"REG_{addr:02X}"
    elif addr < 0x0840:
        return f"RAM_{addr:04X}"
    return None

def disassemble(data, base_addr=0x8000, max_lines=None):
    """Disassemble HC08 binary data"""
    output = []
    pc = 0
    lines = 0
    
    while pc < len(data):
        if max_lines and lines >= max_lines:
            break
            
        addr = base_addr + pc
        opcode = data[pc]
        
        # Check for 0x9E prefix (SP-relative)
        if opcode == 0x9E and pc + 1 < len(data):
            sub_op = data[pc + 1]
            if sub_op in HC08_9E_OPCODES:
                mnem, mode, size = HC08_9E_OPCODES[sub_op]
                size += 1  # Account for prefix
                
                bytes_str = ' '.join(f'{data[pc+i]:02X}' for i in range(min(size, len(data)-pc)))
                
                if mode == "SP1" and pc + 2 < len(data):
                    offset = data[pc + 2]
                    operand = f"${offset:02X},SP"
                elif mode == "SP2" and pc + 3 < len(data):
                    offset = (data[pc + 2] << 8) | data[pc + 3]
                    operand = f"${offset:04X},SP"
                elif mode == "SP1_REL" and pc + 3 < len(data):
                    offset = data[pc + 2]
                    rel = data[pc + 3]
                    if rel > 127:
                        rel -= 256
                    target = addr + size + rel
                    operand = f"${offset:02X},SP, ${target:04X}"
                else:
                    operand = "???"
                
                output.append(f"{addr:04X}: {bytes_str:15s} {mnem:8s} {operand}")
                pc += size
                lines += 1
                continue
        
        if opcode not in HC08_OPCODES:
            output.append(f"{addr:04X}: {opcode:02X}              DB       ${opcode:02X}")
            pc += 1
            lines += 1
            continue
        
        mnem, mode, size = HC08_OPCODES[opcode]
        
        if pc + size > len(data):
            output.append(f"{addr:04X}: {opcode:02X}              DB       ${opcode:02X}")
            pc += 1
            lines += 1
            continue
        
        bytes_str = ' '.join(f'{data[pc+i]:02X}' for i in range(size))
        
        # Format operand based on addressing mode
        if mode == "INH":
            operand = ""
        elif mode == "IMM":
            imm = data[pc + 1]
            operand = f"#${imm:02X}"
        elif mode == "DIR":
            dir_addr = data[pc + 1]
            reg_name = get_reg_name(dir_addr)
            if reg_name:
                operand = f"<{reg_name}"
            else:
                operand = f"<${dir_addr:02X}"
        elif mode == "EXT":
            ext_addr = (data[pc + 1] << 8) | data[pc + 2]
            operand = f"${ext_addr:04X}"
        elif mode == "IX":
            operand = ",X"
        elif mode == "IX1":
            offset = data[pc + 1]
            operand = f"${offset:02X},X"
        elif mode == "IX2":
            offset = (data[pc + 1] << 8) | data[pc + 2]
            operand = f"${offset:04X},X"
        elif mode == "REL":
            rel = data[pc + 1]
            if rel > 127:
                rel -= 256
            target = addr + size + rel
            operand = f"${target:04X}"
        elif mode == "DIR_REL":
            dir_addr = data[pc + 1]
            rel = data[pc + 2]
            if rel > 127:
                rel -= 256
            target = addr + size + rel
            reg_name = get_reg_name(dir_addr)
            if reg_name:
                operand = f"<{reg_name}, ${target:04X}"
            else:
                operand = f"<${dir_addr:02X}, ${target:04X}"
        elif mode == "IMM_REL":
            imm = data[pc + 1]
            rel = data[pc + 2]
            if rel > 127:
                rel -= 256
            target = addr + size + rel
            operand = f"#${imm:02X}, ${target:04X}"
        elif mode == "IX_REL":
            rel = data[pc + 1]
            if rel > 127:
                rel -= 256
            target = addr + size + rel
            operand = f",X, ${target:04X}"
        elif mode == "IX1_REL":
            offset = data[pc + 1]
            rel = data[pc + 2]
            if rel > 127:
                rel -= 256
            target = addr + size + rel
            operand = f"${offset:02X},X, ${target:04X}"
        else:
            operand = "???"
        
        output.append(f"{addr:04X}: {bytes_str:15s} {mnem:8s} {operand}")
        pc += size
        lines += 1
    
    return output

def main():
    bin_file = r"C:\Users\CNC\Documents\PDM_Project\pdm_firmware.bin"
    
    with open(bin_file, 'rb') as f:
        data = f.read()
    
    print(f"Loaded {len(data)} bytes from {bin_file}")
    print(f"Base address: 0x8000")
    print("=" * 60)
    print()
    
    # Disassemble first 200 lines
    output = disassemble(data, base_addr=0x8000, max_lines=200)
    for line in output:
        print(line)
    
    print()
    print("=" * 60)
    print(f"Showing first 200 instructions. Full firmware is {len(data)} bytes.")
    
    # Save full disassembly to file
    output_file = r"C:\Users\CNC\Documents\PDM_Project\pdm_disasm.asm"
    full_output = disassemble(data, base_addr=0x8000)
    
    with open(output_file, 'w') as f:
        f.write("; MC68HC908GZ60 PDM Firmware Disassembly\n")
        f.write("; Base address: 0x8000\n")
        f.write("; Size: {} bytes\n".format(len(data)))
        f.write(";\n")
        f.write("; Auto-generated by hc08_disasm.py\n")
        f.write("=" * 60 + "\n\n")
        f.write("    ORG $8000\n\n")
        for line in full_output:
            f.write(line + "\n")
    
    print(f"\nFull disassembly saved to: {output_file}")

if __name__ == "__main__":
    main()
