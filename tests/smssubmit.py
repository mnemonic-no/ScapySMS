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

print('PDU hex:\t{}'.format(bytes(sms).hex()))
expected_hex = '11000b915155685703f90008001efffe480065006c006c006f00200077006f0072006c00640020000c270ffe'
print('Expected hex:\t{}'.format(expected_hex))

if bytes(sms) == bytearray.fromhex(expected_hex):
    print('Looks okay!')
else:
    print('Something\'s wrong :(')
