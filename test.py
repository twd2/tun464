import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('10.2.2.1', 6666))
s.sendto(b'g' * 4096, ('10.2.2.2', 6666))
data, end_point = s.recvfrom(65536)
print('from', end_point, 'len', len(data))
