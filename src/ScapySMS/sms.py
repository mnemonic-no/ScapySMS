from scapy.all import *

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
        BitEnumField("TP_SRR", 0, 1, {
            0: "0: A status report is not requested",
            1: "1: A status report is requested"
        }),

        # https://en.wikipedia.org/wiki/GSM_03.40#Validity_Period
        BitEnumField("TP_VPF", 2, 2, {
            0: "00: TP-VP field not present",
            2: "10: Relative format",
            1: "01: Enhanced format",
            3: "11: Absolute format"
        }),
        BitEnumField("TP_RD", 0, 1, {
            0: "0: Instruct the SC to accept an SMS-SUBMIT for an SM still held in the SC which has the same TP-MR and the same TP-DA as a previously submitted SM from the same OA.",
            1: "1: Instruct the SC to reject an SMS-SUBMIT for an SM still held in the SC which has the same TP-MR and the same TP-DA as the previously submitted SM from the same OA. In this case an appropriate TP-FCS value will be returned in the SMS-SUBMIT-REPORT."
        }),
        BitEnumField("TP_MTI", 1, 2, {
            0: "00: SMS-DELIVER REPORT (in the direction MS to SC)",
            2: "10: SMS-COMMAND (in the direction MS to SC)",
            1: "01: SMS-SUBMIT (in the direction MS to SC)",
            3: "11: Reserved"
        }),
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
