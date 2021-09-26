import serial
from scapy.all import bytes_hex

class Modem():
    def __init__(self, dev):
        self.dev = dev
        self.initModem()

    def initModem(self):
        self.modem = serial.Serial(self.dev, baudrate=9600, timeout=5.0)

        # Check that modem is working
        self.modem.write('AT\r'.encode('utf8'))
        result=self.modem.read_until(expected=b'OK\r\n')
        if b'OK' not in result:
            print('Modem not responding')
            exit()
        else:
            print('Modem OK')

        # Set PDU mode
        self.modem.write('AT+CMGF=0\r'.encode('utf8'))
        result=self.modem.read_until(expected=b'OK\r\n')
        if b'OK' not in result:
            print('Set PDU mode fail')
            exit()
        else:
            print('Set PDU mode OK')

    def sendPDU(self, data):
        # AT+CMGS
        command = 'AT+CMGS={}\r'.format(len(data)).encode('utf-8')
        self.modem.write(command)
        result=self.modem.read_until(expected=b'>')
        if b'>' not in result:
            print('AT+CMGS fail')
            exit()

        # Send PDU
        command = bytes_hex(data).upper() + b'\x1a'
        self.modem.write(command)

        # Read output
        buffer = b''
        while True:
            byte = self.modem.read(1)
            buffer = buffer + byte
            if b'OK' in buffer:
                print('Send OK')
                break
            if b'ERROR' in buffer:
                print('Send fail')
                break