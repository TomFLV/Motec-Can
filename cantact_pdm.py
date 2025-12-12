#!/usr/bin/env python3
"""
CANtact Pro PDM Communication Tool
Bypasses MoTeC CAN Gateway to communicate directly with PDM using CANtact Pro

Based on reverse engineering of PDM Manager protocol:
- Request ID: 0x7E0 (default, configurable via MoTeC.PDM.RebaseReqId)
- Response ID: 0x7E8 (default, configurable via MoTeC.PDM.RebaseResId)
- CAN Input Base: 0x118 (280) - for PDM operational data
- CAN Output Base: 0x500 (1280) - PDM transmits status here

The MoTeC gateway wraps CAN frames in UDP and uses mDNS for discovery.
With CANtact Pro, we can talk directly to the PDM on CAN.
"""

import struct
import time

# Attempt to import python-can
try:
    import can
    CAN_AVAILABLE = True
except ImportError:
    CAN_AVAILABLE = False
    print("Warning: python-can not installed. Run: pip install python-can")

# ============================================================================
# PDM CAN Protocol Constants
# ============================================================================

# Default CAN IDs for PC <-> PDM communication (ISO-TP style)
PDM_REQUEST_ID = 0x7E0   # PC -> PDM (request)
PDM_RESPONSE_ID = 0x7E8  # PDM -> PC (response)

# Alternative IDs based on serial number (rebased)
# reqbase = 0x600 + (serial % 16) * 0x10
# resbase = 0x608 + (serial % 16) * 0x10

# Operational CAN IDs (for normal PDM operation, not config)
CAN_INPUT_BASE = 0x118   # 280 - Messages from ECU to PDM
CAN_OUTPUT_BASE = 0x500  # 1280 - Status messages from PDM

# CAN Baud rates
CAN_BAUD_RATES = {
    "1M": 1000000,
    "500K": 500000,
    "250K": 250000,
    "125K": 125000,
}

# ============================================================================
# PDM Command Codes (based on reverse engineering)
# ============================================================================

# These are the command bytes sent in CAN frames
# Format appears to be: [CMD, SUB_CMD, DATA...]
PDM_COMMANDS = {
    # Device info
    "GET_SERIAL": 0x01,
    "GET_VERSION": 0x02,
    "GET_HW_ID": 0x03,
    "GET_CHANNELS": 0x04,
    
    # Control
    "SET_HALT": 0x10,
    "CLEAR_HALT": 0x11,
    "RESET": 0x12,
    "RESET_AND_STAY": 0x13,
    
    # Config
    "UNLOCK_CONFIG": 0x20,
    "WRITE_CONFIG": 0x21,
    "GET_CONFIG": 0x22,
    "RELOCK": 0x23,
    
    # Firmware
    "UNLOCK_FIRMWARE": 0x30,
    "WRITE_FIRMWARE": 0x31,
    "GET_FW_STATUS": 0x32,
    
    # Test
    "OUTPUT_TEST": 0x40,
}

# ============================================================================
# CANtact Pro Interface
# ============================================================================

class CANtactPDM:
    """Interface to MoTeC PDM via CANtact Pro"""
    
    def __init__(self, channel='can0', bitrate=500000, interface='slcan'):
        """
        Initialize CANtact Pro connection
        
        Args:
            channel: CAN channel (e.g., 'can0', 'COM3')
            bitrate: CAN baud rate (default 500000)
            interface: python-can interface type
                       'slcan' for CANtact on serial port
                       'socketcan' for Linux SocketCAN
        """
        self.channel = channel
        self.bitrate = bitrate
        self.interface = interface
        self.bus = None
        self.req_id = PDM_REQUEST_ID
        self.res_id = PDM_RESPONSE_ID
        
    def connect(self):
        """Open CAN bus connection"""
        if not CAN_AVAILABLE:
            raise RuntimeError("python-can not installed")
        
        try:
            self.bus = can.interface.Bus(
                channel=self.channel,
                bustype=self.interface,
                bitrate=self.bitrate
            )
            print(f"Connected to CAN bus: {self.channel} @ {self.bitrate} bps")
            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Close CAN bus connection"""
        if self.bus:
            self.bus.shutdown()
            self.bus = None
            print("Disconnected from CAN bus")
    
    def send_frame(self, arb_id, data, timeout=1.0):
        """Send a CAN frame and wait for response"""
        if not self.bus:
            raise RuntimeError("Not connected to CAN bus")
        
        # Ensure data is 8 bytes
        data = bytes(data)[:8].ljust(8, b'\x00')
        
        msg = can.Message(
            arbitration_id=arb_id,
            data=data,
            is_extended_id=False
        )
        
        try:
            self.bus.send(msg)
            print(f"TX: ID=0x{arb_id:03X} Data={data.hex()}")
        except Exception as e:
            print(f"Send failed: {e}")
            return None
        
        # Wait for response
        start = time.time()
        while time.time() - start < timeout:
            response = self.bus.recv(timeout=0.1)
            if response and response.arbitration_id == self.res_id:
                print(f"RX: ID=0x{response.arbitration_id:03X} Data={bytes(response.data).hex()}")
                return response
        
        print("No response received")
        return None
    
    def scan_for_pdm(self, timeout=2.0):
        """Scan for PDM units on the CAN bus"""
        print("Scanning for PDM units...")
        
        # Try sending a get serial number command
        # This is a guess - actual command format needs verification
        response = self.send_frame(
            self.req_id,
            [PDM_COMMANDS["GET_SERIAL"], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            timeout=timeout
        )
        
        if response:
            print("PDM found!")
            return True
        
        # Try alternative IDs
        for offset in range(16):
            alt_req = 0x600 + offset * 0x10
            alt_res = 0x608 + offset * 0x10
            
            print(f"Trying ID 0x{alt_req:03X}...")
            self.req_id = alt_req
            self.res_id = alt_res
            
            response = self.send_frame(
                self.req_id,
                [PDM_COMMANDS["GET_SERIAL"], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                timeout=0.5
            )
            
            if response:
                print(f"PDM found at request ID 0x{alt_req:03X}")
                return True
        
        print("No PDM found")
        return False
    
    def monitor_pdm_status(self, duration=10.0):
        """Monitor PDM status messages on the output base address"""
        print(f"Monitoring PDM status on 0x{CAN_OUTPUT_BASE:03X}+ for {duration}s...")
        
        start = time.time()
        while time.time() - start < duration:
            msg = self.bus.recv(timeout=0.1)
            if msg:
                # Check if it's in the PDM output range
                if CAN_OUTPUT_BASE <= msg.arbitration_id < CAN_OUTPUT_BASE + 0x20:
                    offset = msg.arbitration_id - CAN_OUTPUT_BASE
                    print(f"PDM Status[{offset}]: ID=0x{msg.arbitration_id:03X} Data={bytes(msg.data).hex()}")
    
    def send_can_input(self, message_num, data):
        """Send a CAN input message to the PDM (as if from ECU)"""
        if message_num < 0 or message_num > 3:
            raise ValueError("Message number must be 0-3")
        
        arb_id = CAN_INPUT_BASE + message_num
        data = bytes(data)[:8].ljust(8, b'\x00')
        
        msg = can.Message(
            arbitration_id=arb_id,
            data=data,
            is_extended_id=False
        )
        
        self.bus.send(msg)
        print(f"Sent to PDM: ID=0x{arb_id:03X} Data={data.hex()}")

# ============================================================================
# MoTeC Gateway Protocol (for reference)
# ============================================================================

"""
The MoTeC CAN Gateway uses:
1. mDNS for discovery: _motec-gw-can._udp
2. UDP for CAN frame transport
3. Custom protocol wrapping CAN frames

Gateway commands (from gw_* strings):
- gw_set=%d     : Set parameter
- gw_examine=%d : Examine/query
- gw_overlap=%d : Overlap setting
- gw_ver=%d     : Version query
- gw_name=%s    : Name query
- gw_pkt=%d     : Packet setting

VIM Configuration (VIMCFG_*):
- VIMCFG_CRC
- VIMCFG_HW_NUM
- VIMCFG_SERIAL_NUM
- VIMCFG_VERSION
- VIMCFG_CAN_BUS
- VIMCFG_PACKET_SIZE
- VIMCFG_LEN

CAN interface selection:
- canif=%d      : Select CAN interface number
- cankbaud=%d   : Set CAN baud rate in kbps

TXT record (mDNS):
- txtvers=1
- TxRate
"""

# ============================================================================
# Main
# ============================================================================

def print_usage():
    print("""
CANtact Pro PDM Communication Tool

Usage:
  python cantact_pdm.py scan [port]        - Scan for PDM units
  python cantact_pdm.py monitor [port]     - Monitor PDM status messages
  python cantact_pdm.py send [port] [data] - Send CAN input to PDM

Examples:
  python cantact_pdm.py scan COM3
  python cantact_pdm.py monitor /dev/ttyUSB0
  python cantact_pdm.py send COM3 01020304

CANtact Pro interface:
  Windows: COM3, COM4, etc.
  Linux: /dev/ttyACM0, /dev/ttyUSB0
  
Ensure CANtact is in slcan mode (green LED).
Default baud rate: 500 kbps
""")

def main():
    import sys
    
    if len(sys.argv) < 2:
        print_usage()
        return
    
    command = sys.argv[1].lower()
    port = sys.argv[2] if len(sys.argv) > 2 else 'COM3'
    
    # Create PDM interface
    pdm = CANtactPDM(channel=port, bitrate=500000, interface='slcan')
    
    if not pdm.connect():
        return
    
    try:
        if command == 'scan':
            pdm.scan_for_pdm()
        
        elif command == 'monitor':
            pdm.monitor_pdm_status(duration=30.0)
        
        elif command == 'send':
            if len(sys.argv) > 3:
                data = bytes.fromhex(sys.argv[3])
                pdm.send_can_input(0, data)
            else:
                print("Need data to send (hex string)")
        
        else:
            print(f"Unknown command: {command}")
            print_usage()
    
    finally:
        pdm.disconnect()

if __name__ == "__main__":
    main()
