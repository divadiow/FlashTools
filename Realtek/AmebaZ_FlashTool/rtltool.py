#!/usr/bin/env python3
# RTL871xBx ROM Bootloader Utility Ver 12.01.2018
# Created on: 10.10.2017
# Author: pvvx
# Py3: divadiow
# https://github.com/openshwprojects/OpenBK7231T_App
# Support: https://www.elektroda.com/rtvforum/forum390.html

import sys
import struct
import serial
import platform
import time
import argparse
import os
import io

# Protocol bytes
SOH = b'\x01'
STX = b'\x02'
EOT = b'\x04'
ACK = b'\x06'
DLE = b'\x10'
NAK = b'\x15'
CAN = b'\x18'

CMD_USB   = b'\x05'  # UART Set Baud
CMD_XMD   = b'\x07'  # Go xmodem mode (write RAM/Flash mode)
CMD_EFS   = b'\x17'  # Erase Flash Sectors
CMD_RBF   = b'\x19'  # Read Block Flash
CMD_ABRT  = b'\x1B'  # End xmodem mode (write RAM/Flash mode)
CMD_GFS   = b'\x21'  # FLASH Get Status
CMD_SFS   = b'\x26'  # FLASH Set Status

# Protocol Mode
MODE_RTL = 0      # Rtl mode
MODE_XMD = 1      # xmodem mode
MODE_UNK1 = 3     # Unknown mode, test 1
MODE_UNK2 = 4     # Unknown mode, test 2

# Default baudrate
RTL_ROM_BAUD = 1500000

RTL_READ_BLOCK_SIZE = 1024
RTL_FLASH_SECTOR_SIZE = 4096

''' class RTL xModem '''
class RTLXMD:

    def __init__(self, port=0, baud=RTL_ROM_BAUD, timeout=1):
        self.mode = MODE_UNK1
        try:
            self._port = serial.Serial(port, baud, timeout=timeout)
        except Exception as e:
            print("Error: Open %s, %d baud! (%s)" % (port, baud, str(e)))
            sys.exit(-1)

    def writecmd(self, cmd, ok=ACK):
        if self._port.write(cmd):
            char = self._port.read(1)
            if char:
                if char == ok:
                    return True
        return False

    def WaitNAK(self):
        chr_count = 128
        while True:
            char = self._port.read(1)
            if char:
                if char == NAK:
                    return True
            else:
                return None
            chr_count -= 1
            if chr_count == 0:
                return False

    def sync(self, mode=MODE_RTL, flush=True, ready=7):
        if flush:
            # In pyserial 3.x, use reset_output_buffer() and reset_input_buffer()
            self._port.reset_output_buffer()
            self._port.reset_input_buffer()
        error_count = 0
        cancel = 0
        while True:
            char = self._port.read(1)
            if char:
                if char == b'\x00':
                    continue
                elif char == NAK:
                    # standard checksum requested (NAK)
                    if mode != self.mode:
                        if self.mode < MODE_UNK1:
                            if mode == MODE_RTL:
                                if self.writecmd(CMD_ABRT, CAN):
                                    self.mode = MODE_RTL
                                    break
                            elif mode == MODE_XMD:
                                if self.writecmd(CMD_XMD):
                                    self.mode = MODE_XMD
                                    break
                        else:
                            if mode == MODE_XMD:
                                if self.writecmd(CMD_XMD):
                                    self.mode = MODE_XMD
                                    break
                        self.mode = MODE_RTL
                    break
                elif char == CAN:
                    # received CAN
                    if cancel:
                        # Transmission canceled: received 2xCAN at start-sequence
                        return False
                    else:
                        # Cancellation at start sequence
                        cancel = 1
            else:
                if self.mode == MODE_UNK1:
                    if self.writecmd(CMD_XMD):
                        self.mode = MODE_XMD
                        if mode == MODE_XMD:
                            return True
                        if self.writecmd(CMD_ABRT, CAN):
                            self.mode = MODE_RTL
                            return True
                    self.mode = MODE_UNK2
                elif self.mode == MODE_UNK2:
                    if self.writecmd(CMD_ABRT, CAN):
                        self.mode = MODE_RTL
                        if mode == MODE_RTL:
                            return True
                        if self.writecmd(CMD_XMD):
                            self.mode = MODE_XMD
                            return True
                    self.mode = MODE_UNK1
            error_count += 1
            if error_count > ready:
                if self.mode == MODE_XMD:
                    # send error: error_count reached limit, aborting.
                    self._port.write(CAN)
                    self._port.write(CAN)
                return False
        return True

    def ModeXmodem(self):
        if self.sync():
            ret = self.writecmd(CMD_XMD)
            if ret is True:
                self.mode = MODE_XMD
            return ret
        return None

    def RtlMode(self):
        if self.sync():
            ret = self.writecmd(CMD_ABRT, CAN)
            if ret is True:
                self.mode = MODE_RTL
            return ret
        return None

    def GetFlashStatus(self):
        if self.sync():
            self._port.write(CMD_GFS)
            return self._port.read(1)
        return None

    def SetFlashStatus(self, status):
        if self.sync():
            # Concatenate the CMD_SFS byte with the status byte.
            if self.writecmd(CMD_SFS + bytes([status])):
                return self.GetFlashStatus()
        return None

    def ReadBlockFlash(self, stream, offset=0, size=0x200000):
        # Read sectors size: 4 block 1024 bytes, else not set ACK!
        count = (size + RTL_FLASH_SECTOR_SIZE - 1) // RTL_FLASH_SECTOR_SIZE
        offset &= 0xffffff
        if count > 0 and count < 0x10000 and offset >= 0:  # 1 byte .. 16 Mbytes
            ret = self.sync()
            if ret:
                # Use offset // 0x10000 for integer division.
                ret = self._port.write(struct.pack('<BHBH', CMD_RBF[0], offset & 0xffff, (offset // 0x10000) & 0xff, count))
                count *= 4
                if ret:
                    for _ in range(count):
                        data = self._port.read(RTL_READ_BLOCK_SIZE)
                        if data:
                            ret = self._port.write(ACK)
                            if ret:
                                if size > RTL_READ_BLOCK_SIZE:
                                    stream.write(data)
                                elif size > 0:
                                    stream.write(data[:size])
                            else:
                                return ret
                        else:
                            return False
                        size -= RTL_READ_BLOCK_SIZE
                    if size <= 0:
                        ret = self.sync()
        else:
            ret = False
        return ret

    def connect(self):
        # issue reset-to-bootloader:
        # RTS = either RESET (both active low = chip in reset)
        # DTR = GPIOA_30 (active low = boot to flasher)
        self._port.setDTR(False)
        self._port.setRTS(True)
        time.sleep(0.05)
        self._port.setDTR(True)
        self._port.setRTS(False)
        time.sleep(0.05)
        self._port.setDTR(False)
        return self.GetFlashStatus()

    def EraseSectorsFlash(self, offset=0, size=0x200000):
        count = (size + RTL_FLASH_SECTOR_SIZE - 1) // RTL_FLASH_SECTOR_SIZE
        offset &= 0xfff000
        if count > 0 and count < 0x10000 and offset >= 0:  # 1 byte .. 16 Mbytes
            for i in range(count):
                ret = self.sync()
                if ret:
                    # Uncomment the next line for progress output if desired.
                    # print('\r%d' % i, end='')
                    ret = self.writecmd(struct.pack('<BHBH', CMD_EFS[0], offset & 0xffff, (offset // 0x10000) & 0xff, 1))
                    if not ret:
                        return ret
                offset += RTL_FLASH_SECTOR_SIZE
            ret = self.sync()
        else:
            ret = False
        return ret

    def calc_checksum(self, data, checksum=0):
        # In Python 3, iterating over bytes gives integers.
        if platform.python_version_tuple() >= ('3', '0', '0'):
            return (sum(data) + checksum) % 256
        else:
            return (sum(map(ord, data)) + checksum) % 256

    def send_xmodem(self, stream, offset, size, retry=3):
        ret = self.sync(MODE_XMD)
        if ret:
            sequence = 1
            while size > 0:
                if size <= 128:
                    packet_size = 128
                    cmd = SOH
                else:
                    packet_size = 1024
                    cmd = STX
                rdsize = packet_size
                if size < rdsize:
                    rdsize = size
                data = stream.read(rdsize)
                if not data:  # end of stream
                    print("send: at EOF")
                    return False
                data = data.ljust(packet_size, b'\xFF')
                # Build packet: <cmd><seq><255-seq><offset> then data, then checksum.
                pkt = struct.pack('<BBBI', cmd[0], sequence, 0xff - sequence, offset) + data
                crc = self.calc_checksum(pkt[3:])
                pkt += struct.pack('<B', crc)
                error_count = 0
                while True:
                    ret = self.writecmd(pkt)
                    if ret:
                        sequence = (sequence + 1) % 0x100
                        offset += packet_size
                        size -= rdsize
                        break
                    else:
                        error_count += 1
                        if error_count > retry:
                            return False

            ret = self.writecmd(EOT)  # if write SRAM -> (*0x10002000)()
            self.mode = MODE_RTL
        return ret

    def WriteBlockSRAM(self, stream, offset=0x10002000, size=0x1000, retry=3):
        offset &= 0x00ffffff
        offset |= 0x10000000
        return self.send_xmodem(stream, offset, size, retry)

    def WriteBlockFlash(self, stream, offset=0x10010000, size=0x1000, retry=3):
        offset &= 0x00ffffff
        offset |= 0x08000000
        return self.send_xmodem(stream, offset, size, retry)

def arg_auto_int(x):
    return int(x, 0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RT871xBx ROM Bootloader Utility', prog='rtltool')

    parser.add_argument(
        '--port', '-p',
        help='Serial port device',
        default='COM0')
    parser.add_argument(
        '--go','-g', action="store_true",
        help='Run after performing the operation')

    subparsers = parser.add_subparsers(
        dest='operation',
        help='Run rtlbtool {command} -h for additional help')

    parser_read_flash = subparsers.add_parser(
        'rf',
        help='Read Flash data to binary file')
    parser_read_flash.add_argument('address', help='Start address', type=arg_auto_int)
    parser_read_flash.add_argument('size', help='Size of region', type=arg_auto_int)
    parser_read_flash.add_argument('filename', help='Name of binary file')

    parser_write_flash = subparsers.add_parser(
        'wf',
        help='Write a binary file to Flash data')
    parser_write_flash.add_argument('address', help='Start address', type=arg_auto_int)
    parser_write_flash.add_argument('filename', help='Name of binary file')

    parser_write_mem = subparsers.add_parser(
        'wm',
        help='Write a binary file to SRAM memory')
    parser_write_mem.add_argument('address', help='Start address', type=arg_auto_int)
    parser_write_mem.add_argument('filename', help='Name of binary file')

    parser_erase_flash = subparsers.add_parser(
        'es',
        help='Erase Sectors Flash')
    parser_erase_flash.add_argument('address', help='Start address', type=arg_auto_int)
    parser_erase_flash.add_argument('size', help='Size of region', type=arg_auto_int)

    parser_get_status_flash = subparsers.add_parser(
        'gf',
        help='Get Flash Status register')

    parser_set_status_flash = subparsers.add_parser(
        'sf',
        help='Set Flash Status register')
    # Added an argument for flash status value.
    parser_set_status_flash.add_argument('value', help='Flash status value', type=arg_auto_int)

    parser_boot_flash = subparsers.add_parser(
        'bf',
        help='Start boot flash')
    parser_go_monitor = subparsers.add_parser(
        'gm',
        help='Go ROM Monitor')

    args = parser.parse_args()
    rtl = RTLXMD(args.port)
    print("Connecting...")
    if rtl.connect():
        if args.operation == 'wf':
            stream = open(args.filename, 'rb')
            size = os.path.getsize(args.filename)
            if size < 1:
                stream.close()
                print("Error: File size = 0!")
                sys.exit(-1)
            offset = args.address & 0x00ffffff
            offset |= 0x08000000
            print("Write Flash data 0x%08x to 0x%08x from file: %s ..." % (offset, offset + size, args.filename))
            if not rtl.WriteBlockFlash(stream, args.address, size):
                stream.close()
                print("Error: Write Flash!")
                sys.exit(-2)
            stream.close()

        elif args.operation == 'rf':
            print("Read Flash data from 0x%08x to 0x%08x in file: %s ..." % (args.address, args.address + args.size, args.filename))
            stream = open(args.filename, 'wb')
            if not rtl.ReadBlockFlash(stream, args.address, args.size):
                stream.close()
                print("Error!")
                sys.exit(-2)
            stream.close()

        elif args.operation == 'wm':
            stream = open(args.filename, 'rb')
            size = os.path.getsize(args.filename)
            if size < 1:
                stream.close()
                print("Error: File size = 0!")
                sys.exit(-1)
            offset = args.address & 0x00ffffff
            offset |= 0x10000000
            print("Write SRAM at 0x%08x to 0x%08x from file: %s ..." % (args.address, args.address + size, args.filename))
            if not rtl.WriteBlockSRAM(stream, args.address, size):
                stream.close()
                print("Error: Write Flash!")
                sys.exit(-2)
            stream.close()
            print("Done!")
            sys.exit(0)

        elif args.operation == 'es':
            count = (args.size + RTL_FLASH_SECTOR_SIZE - 1) // RTL_FLASH_SECTOR_SIZE
            size = count * RTL_FLASH_SECTOR_SIZE
            offset = args.address & 0xfff000
            print("Erase Flash %d sectors, data from 0x%08x to 0x%08x ..." % (count, offset, offset + size))
            if rtl.EraseSectorsFlash(offset, size):
                print("Done!")
                sys.exit(0)
            print("Error: Erase Flash sectors!")
            sys.exit(-2)

        elif args.operation == 'gf':
            fsta = rtl.GetFlashStatus()
            if fsta:
                print("Flash Status value: 0x%02x" % (fsta[0]))
                sys.exit(0)
            print("Error: Get Flash Status!")
            sys.exit(-2)

        elif args.operation == 'sf':
            print("Set Flash Status value: 0x%02x" % (args.value & 0xFF))
            if rtl.SetFlashStatus(args.value & 0xFF):
                sys.exit(0)
            print("Error: Set Flash Status!")
            sys.exit(-2)

        elif args.operation == 'bf':
            print("BOOT_ROM_FromFlash()...")  # ROM-Call:00005404
            stream = io.BytesIO(b'\x05\x54\x00\x00')
            if not rtl.WriteBlockSRAM(stream, 0x10002000, 4):
                stream.close()
                print("Error!")
                sys.exit(-2)
            print("Done!")
            rtl._port.close()
            rtl._port.baudrate = 115200
            rtl._port.open()
            rtl._port.timeout = 1
            sio = io.TextIOWrapper(io.BufferedRWPair(rtl._port, rtl._port))
            # Print several lines read from the serial interface.
            print(sio.readline(), sio.readline(), sio.readline(), sio.readline(), sio.readline())
            sys.exit(0)

        elif args.operation == 'gm':
            # For ROM Monitor, send a specific binary blob.
            stream = io.BytesIO(b'\x19\x20\x00\x10\x19\x20\x00\x10\x19\x20\x00\x10\x19\x20\x00\x10\x19\x20\x00\x10\x19\x20\x00\x10\x00\x00\x00\x00\x08\xb5\x02\x4c\x4f\xf4\x7a\x70\xa0\x47\xfb\xe7\x05\x22\x00\x00')
            if not rtl.WriteBlockSRAM(stream, 0x10002000, 40):
                stream.close()
                print("Error!")
                sys.exit(-2)
            print("Done!")
            sys.exit(0)
    else:
        print("Failed to connect device on", args.port, "!")
        sys.exit(-2)

    if args.go:
        if not rtl.WaitNAK() or rtl.writecmd(CMD_GFS, b'\x00') is None:
            print("Error: Sync!")
            sys.exit(-2)
        print("BOOT FromFlash...")  # ROM-Call:00005404
        stream = io.BytesIO(b'\x05\x54\x00\x00')
        if not rtl.WriteBlockSRAM(stream, 0x10002000, 4):
            stream.close()
            print("Error!")
            sys.exit(-2)
    print("Done!")
    sys.exit(0)
