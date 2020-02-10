import binascii
import sys
import serial
import os
sys.path.insert(0,os.getcwd() + '../libs')
from colorama import Fore
from scapy.utils import raw

# USB Serial commands
NRF52_CMD_DATA = '\xA7'
NRF52_CMD_CHECKSUM_ERROR = '\xA8'
NRF52_CMD_CONFIG_AUTO_EMPTY_PDU = '\xA9'
NRF52_CMD_CONFIG_ACK = '\xAA'
NRF52_CMD_BOOTLOADER_SEQ1 = '\xA6'
NRF52_CMD_BOOTLOADER_SEQ2 = '\xC7'
NRF52_CMD_LOG = '\x7F'


# Driver class
class NRF52Dongle:
    n_debug = False
    n_log = False
    event_counter = 0

    # Constructor ------------------------------------
    def __init__(self, port_name, baudrate, debug=False, logs=True):
        self.serial = serial.Serial(port_name, baudrate, timeout=1)

        self.n_log = logs
        self.n_debug = debug

        if self.n_debug:
            print('NRF52 Dongle: Instance started')

    def close(self):
        print('NRF52 Dongle closed')

    # RAW functions ---------------------------
    def raw_send(self, pkt):
        raw_pkt = bytearray(pkt[:-3])  # Cut the 3 bytes CRC
        crc = chr(sum(raw_pkt) & 0xFF)  # Calculate CRC of raw packet data
        pkt_len = len(raw_pkt)  # Get raw packet data length
        l = bytearray([pkt_len & 0xFF, (pkt_len >> 8) & 0xFF])  # Pack length in 2 bytes (little infian)
        data = NRF52_CMD_DATA + l + raw_pkt + crc
        self.serial.write(data)

        if self.n_debug:
            print('Bytes sent: ' + binascii.hexlify(data).upper())

        return data

    def send(self, scapy_pkt, print_tx=True):
        self.raw_send(raw(scapy_pkt))
        if print_tx:
            print(Fore.CYAN + "TX ---> " + scapy_pkt.summary()[7:])

    def raw_receive(self):
        c = self.serial.read(1)
        # Receive BLE adv or channel packets
        if c == NRF52_CMD_DATA:
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            sz = lb | (hb << 8)
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            evt_counter = lb | (hb << 8)
            data = bytearray(self.serial.read(sz))
            checksum = ord(self.serial.read(1))
            if (sum(data) & 0xFF) == checksum:
                # If the data received is correct
                self.event_counter = evt_counter

                if self.n_debug:
                    print("Hex: " + binascii.hexlify(data).upper())
                return data
        # Receive logs from dongle
        elif c == NRF52_CMD_LOG:
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            sz = lb | (hb << 8)
            data = self.serial.read(sz)
            if self.n_log:
                print(data)
        elif c == NRF52_CMD_CHECKSUM_ERROR:
            print(Fore.RED + "NRF52_CMD_CHECKSUM_ERROR")
            sys.exit(0)
        return None
