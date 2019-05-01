include config.mk

.PHONY: all
all: tun464

tun464: main.o common.o utils.o 4to6.o 6to4.o
	gcc -O2 -Wall $^ -o $@ -lpthread

%.o: %.c common.h utils.h 4to6.h 6to4.h
	gcc -O2 -Wall -c $< -o $@

.PHONY: run
run: tun464
	sudo ./tun464 tun464 $(PREFIX_A) $(PREFIX_B)

.PHONY: run2
run2: tun464
	sudo ./tun464 tun464 $(PREFIX_B) $(PREFIX_A)

.PHONY: setup
setup:
	sudo ip addr add 10.2.2.1/32 dev tun464-ipv4
	sudo ip link set tun464-ipv4 up
	sudo ip link set tun464-ipv4 mtu $(IPV4_MTU)
	sudo ip link set tun464-ipv6 up
	sudo ip route add $(PREFIX_A)/96 dev tun464-ipv6
	sudo ip route add 10.2.2.2/32 dev tun464-ipv4

.PHONY: setup2
setup2:
	sudo ip addr add 10.2.2.2/32 dev tun464-ipv4
	sudo ip link set tun464-ipv4 up
	sudo ip link set tun464-ipv4 mtu $(IPV4_MTU)
	sudo ip link set tun464-ipv6 up
	sudo ip route add $(PREFIX_B)/96 dev tun464-ipv6
	sudo ip route add 10.2.2.1/32 dev tun464-ipv4

.PHONY: clean
clean:
	-rm tun464 *.o
