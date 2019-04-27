include config.mk

.PHONY: all
all: tun464

tun464: main.c
	gcc -O2 -Wall $^ -o $@

.PHONY: run
run: tun464
	sudo ./tun464 tun464 $(PREFIX_A) $(PREFIX_B)

.PHONY: run2
run2: tun464
	sudo ./tun464 tun464 $(PREFIX_B) $(PREFIX_A)

.PHONY: setup
setup:
	sudo ip addr add 10.2.2.1/32 dev tun464
	sudo ip link set tun464 up
	sudo ip route add $(PREFIX_A)/96 dev tun464
	sudo ip route add 10.2.2.2/32 dev tun464

.PHONY: setup2
setup2:
	sudo ip addr add 10.2.2.2/32 dev tun464
	sudo ip link set tun464 up
	sudo ip route add $(PREFIX_B)/96 dev tun464
	sudo ip route add 10.2.2.1/32 dev tun464

.PHONY: clean
clean:
	-rm tun464
