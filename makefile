install:
	@gcc -Wall -Werror -o hider libg/*.c *.c -lcurl -ljson-c
	@mv hider /usr/bin/
	@if [ ! -e /etc/hider ]; then mkdir /etc/hider; fi
	@chmod 0777 /etc/hider
	@if [ ! -e /etc/hider/torrc ]; then cp ./conf/torrc /etc/hider/; fi

remove:
	@rm /usr/bin/hider
	@rm -r /etc/hider