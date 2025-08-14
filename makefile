program3_gward22_firewall_log: main.o firewall_log.o
		gcc -g -o program3_gward22_firewall_log main.o firewall_log.o

main.o: main.c firewall_log.h
		gcc -g -c -I. main.c

firewall_log.o: firewall_log.c firewall_log.h
		gcc -g -c -I. firewall_log.c

clean:
		rm -f *.o program3_gward22_firewall_log

