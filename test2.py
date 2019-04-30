import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('10.2.2.2', 6666))
while True:
    data, end_point = s.recvfrom(65536)
    print('from', end_point, 'len', len(data))
    s.sendto(data, end_point)
