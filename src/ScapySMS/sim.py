from scapy.all import *

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