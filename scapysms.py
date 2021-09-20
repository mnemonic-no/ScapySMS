from scapy.all import *
import serial

class NibbleAddressDigits(Field):
    """ NibbleAddress """
    __slots__ = ["length_from"]

    def __init__(self, name, default, length_from):
        Field.__init__(self, name, default)
        self.length_from = length_from

    def countBytes(self, len_nibble):
        if (len_nibble % 2) == 0:
            len_bytes = int(len_nibble / 2)
        else:
            len_bytes = int((len_nibble + 1) / 2)
        return len_bytes

    def i2h(self, pkt, x):
        len_nibble = self.length_from(pkt)
        len_bytes = self.countBytes(len_nibble)
        s = ''
        for byte in x[:len_bytes]:
            high, low = byte >> 4, byte & 0x0F
            s = s + str(low)
            if len(s) < len_nibble:
                s = s + str(high)
        return int(s)

    def i2len(self, pkt, x):
        return len(x)

    def addfield(self, pkt, s, val):
        ba = bytearray()
        for first, second in itertools.zip_longest(val[::2], val[1::2], fillvalue=0x0F):
            res = int(first) >> 0 | int(second) << 4
            ba.append(res)
        return s+bytes(ba)

    def getfield(self, pkt, s):
        len_nibble = self.length_from(pkt)
        len_bytes = self.countBytes(len_nibble)
        return s[len_bytes:], s[:len_bytes]

class Address(Packet):
    name = "Address"
    fields_desc = [
        FieldLenField("Length", None, fmt="B", length_of="Digits"),
        BitEnumField("Extension", 1, 1, {
            1: "No extension",
        }),
        BitEnumField("Type_of_number", 0, 3, {
            0: "Unknown",
            1: "International number",
            2: "National number",
            3: "Network specific number",
            4: "Subscriber number",
            5: "Alphanumeric",
            6: "Abbreviated number",
            7: "Reserved for extension",
        }),
        BitEnumField("Numbering_plan", 1, 4, {
            0: "Unknown",
            1: "ISDN/telephone numbering plan (E.164/E.163)",
            3: "Data numbering plan (X.121)",
            4: "Telex numbering plan",
            5: "Service Centre Specific plan",
            6: "Service Centre Specific plan",
            8: "National numbering plan",
            9: "Private numbering plan",
            10: "ERMES numbering plan (ETSI DE/PS 3 01 3)",
            15: "Reserved for extension"
        }),
        NibbleAddressDigits('Digits', '123456', length_from=lambda pkt:pkt.Length)
    ]
    def extract_padding(self, p):
        return "", p

TP_VPF_map = {
        0: 0,
        1: 7,
        2: 1,
        3: 7
    }

def TP_UDL_calc(pkt):
    if pkt.TP_UDHI == 1:
        udl = pkt.TP_UDL - pkt.TP_UDHL - 1
    else:
        udl = pkt.TP_UDL
    return udl

class SMSSubmit(Packet):
    name = "SMS-SUBMIT"
    # https://en.wikipedia.org/wiki/GSM_03.40#TPDU_Fields
    fields_desc = [
        BitEnumField("TP_RP", 0, 1, {
            0: "0: TP-Reply-Path parameter is not set in this SMS-SUBMIT/DELIVER",
            1: "1: TP-Reply-Path parameter is set in this SMS-SUBMIT/DELIVER"
        }),
        BitEnumField("TP_UDHI", 0, 1, {
            0: "0: The TP-UD field contains only the short message",
            1: "1: The beginning of the TP-UD field contains a Header in addition to the short message"
        }),
        BitField("TP_SRR", 0, 1),

        # https://en.wikipedia.org/wiki/GSM_03.40#Validity_Period
        BitEnumField("TP_VPF", 2, 2, {
            0: "00: TP-VP field not present",
            2: "10: Relative format",
            1: "01: Enhanced format",
            3: "11: Absolute format"
        }),
        BitField("TP_RD", 0, 1),
        BitField("TP_MTI", 1, 2),
        ByteField("TP_MR", 0),
        PacketField("TP_DA", Address(), Address),
        ByteField("TP_PID", 0),
        ByteField("TP_DCS", 0),
        XStrLenField("TP_VP", 0, length_from=lambda pkt: TP_VPF_map.get(pkt.TP_VPF)),

        MultipleTypeField(
            [
                # If UDH
                (FieldLenField("TP_UDL", None, fmt="B", length_of="TP_UD", adjust=lambda pkt,x: x + len(pkt.TP_UDH) + 1), lambda pkt: pkt.TP_UDHI==1)
            ],
            FieldLenField("TP_UDL", None, fmt="B", length_of="TP_UD")  # By default
        ),

        ConditionalField(FieldLenField("TP_UDHL", None, fmt="B", length_of="TP_UDH"), lambda pkt: pkt.TP_UDHI==1),
        ConditionalField(XStrLenField("TP_UDH", 0, length_from=lambda pkt: pkt.TP_UDHL), lambda pkt: pkt.TP_UDHI==1),
        XStrLenField("TP_UD", 0, length_from=TP_UDL_calc)
    ]

class CommandPacket(Packet):
    name = "Command Packet"
    fields_desc = [
        # ETSI TS 131 115 / 4.2 Structure of the Command Packet contained in a Single Short Message Point to Point
        ShortField("CPL", None),
        ByteField("CHL", None),

        # ETSI TS 102 225 / 5.1.1 Coding of the SPI
        BitEnumField("SPI1_b8b7b6", 0, 3, {
            0: "00: Reserved"
        }),
        BitEnumField("SPI1_b5b4", 0, 2, {
            0: "00: No counter available",
            1: "01: Counter available; no replay or sequence checking",
            2: "10: Process if and only if counter value is higher than the value in the RE",
            3: "11: Process if and only if counter value is one higher than the value in the RE"
        }),
        BitEnumField("SPI1_b3", 0, 1, {
            0: "0: No Ciphering",
            1: "1: Ciphering"
        }),
        BitEnumField("SPI1_b2b1", 0, 2, {
            0: "00: No RC, CC or DS",
            1: "01: Redundancy Check",
            2: "10: Cryptographic Checksum",
            3: "11: Digital Signature"
        }),
        BitField("SPI2_b8b7", 0, 2),
        BitField("SPI2_b6", 0, 1),
        BitField("SPI2_b5", 0, 1),
        BitField("SPI2_b4b3", 0, 2),
        BitField("SPI2_b2b1", 0, 2),

        # ETSI TS 102 225 / 5.1.2 Coding of the KIc
        BitField("KIc_b8b7b6b5", 0, 4),
        BitField("KIc_b4b3", 0, 2),
        BitEnumField("KIc_b2b1", 0, 2, {
            0: "00: Algorithm known implicitly by both entities",
            1: "01: DES",
            2: "10: AES",
            3: "11: proprietary Implementations"
        }),

        # ETSI TS 102 225 / 5.1.3 Coding of the KID
        BitField("KID_b8b7b6b5", 0, 4),
        BitField("KID_b4b3", 0, 2),
        BitField("KID_b2b1", 0, 2),
        XNBytesField("TAR", 0, 3),
        XNBytesField("CNTR", 0, 5),
        XByteField("PCNTR", 0),
        XStrLenField("RC_CC_DS", b'\x00\x00\x00\x00', length_from=lambda pkt: pkt.CHL - 13)
        ]
    def post_build(self, p, pay):
        if self.CHL is None:
            chl = len(self.RC_CC_DS) + 13
            chl = chl.to_bytes(1, 'big')
            p = p[:2] + chl + p[3:]
        if self.CPL is None:
            cpl = len(p) + len(pay) - 2
            cpl = cpl.to_bytes(2, 'big')
            p = cpl + p[2:]
        return p + pay

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
