# ScapySMS
A Scapy implementation of SMS-SUBMIT and (U)SIM Application Toolkit command packets.

This framework is designed to assist with fuzzing SIM card applications and, more generally, SMS systems as a whole. Because this project uses the [Scapy framework](https://scapy.readthedocs.io/en/latest/index.html), it's possible to have control over the *entire* packet. This was the key feature that inspired the creation of this project.

Functionality for sending SMS messages via AT commands to a modem is also included.

# Install
```python3
pip install /directory/with/ScapySMS/
```

# How to use
It is nearly impossible to use this framework without having the GSM specification side by side as a reference. Some notes on the relevant GSM documents can be found in this packages's source. Though you'll probably want to start here:

* https://en.wikipedia.org/wiki/GSM_03.40 - SMS specification summarized
* [GSM 03.40](https://www.etsi.org/deliver/etsi_gts/03/0340/05.03.00_60/gsmts_0340v050300p.pdf) - Official SMS specification
* [ETSI TS 102 225](https://www.etsi.org/deliver/etsi_ts/102200_102299/102225/09.00.00_60/ts_102225v090000p.pdf) - (U)SIM Application Toolkit command packets

## Building a SMS-SUBMIT PDU
```python3
import ScapySMS

sms = ScapySMS.SMSSubmit()
sms.TP_RP = 0
sms.TP_UDHI = 0
sms.TP_SRR = 0
sms.TP_VPF = 10
sms.TP_RD = 0
sms.TP_MTI = 1
sms.TP_MR = 0

myaddr = ScapySMS.Address()
myaddr.Type_of_number = 1 # International format, includes country code
myaddr.Digits = '15558675309'
sms.TP_DA = myaddr

sms.TP_PID = 0
sms.TP_DCS = 8 # UTF-16
sms.TP_VP = b'\x00' # 5 minutes
sms.TP_UD = 'Hello world ✌️'.encode('utf-16')
sms.show2()

print('PDU hex: {}'.format(bytes(sms).hex()))
```

```
###[ SMS-SUBMIT ]### 
  TP_RP     = 0: TP-Reply-Path parameter is not set in this SMS-SUBMIT/DELIVER
  TP_UDHI   = 0: The TP-UD field contains only the short message
  TP_SRR    = 0: A status report is not requested
  TP_VPF    = 10: Relative format
  TP_RD     = 0: Instruct the SC to accept an SMS-SUBMIT for an SM still held in the SC which has the same TP-MR and the same TP-DA as a previously submitted SM from the same OA.
  TP_MTI    = 01: SMS-SUBMIT (in the direction MS to SC)
  TP_MR     = 0
  \TP_DA     \
   |###[ Address ]###
   |  Length    = 11
   |  Extension = No extension
   |  Type_of_number= International number
   |  Numbering_plan= ISDN/telephone numbering plan (E.164/E.163)
   |  Digits    = 15558675309
  TP_PID    = 0
  TP_DCS    = 8
  TP_VP     = 00
  TP_UDL    = 30
  TP_UD     = fffe480065006c006c006f00200077006f0072006c00640020000c270ffe

PDU hex: 11000b915155685703f90008001efffe480065006c006c006f00200077006f0072006c00640020000c270ffe
```

## Sending a SMS to a modem
```python3
m = ScapySMS.Modem('/dev/ttyUSB2')
m.sendPDU(sms)
```

## (U)SIM Application Toolkit command packets
I don't have any good examples to show here, but you can decode a packet from hex like this:

```python3
bytes = bytes.fromhex(yourhex)
p = ScapySMS.CommandPacket(bytes)
p.show2()
```

# Testbed suggestions
I recommend checking out the [QCSuper](https://github.com/P1sec/QCSuper) project. Paired with the right Qualcomm USB modem / Android phone you can use this to create GSM packet captures. This is extremely helpful for seeing how data is sent out from your modem, as well as seeing what the data looks like when it's received.

[SCAT](https://github.com/fgsect/scat) is another tool that works similarly.

# Learn more
Adaptive Mobile's [Simjacker technical report](https://simjacker.com/) is a good practical example of what can be found when digging into these old technologies.

Also:
* https://opensource.srlabs.de/projects/simtester/
* https://www.youtube.com/watch?v=DHhYz9euDB8
* https://media.defcon.org/DEF%20CON%2021/DEF%20CON%2021%20presentations/DEF%20CON%2021%20-%20Bogdan-Alecu-Attacking-SIM-Toolkit-with-SMS-WP.pdf
