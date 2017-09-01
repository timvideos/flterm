#ifndef __XMODEM_H
#define __XMODEM_H


struct xmodem_packet {
	unsigned char start;
	unsigned char num;
	unsigned char num_comp;
	unsigned char payload[1024];
	unsigned char crc[2];
} __attribute__((packed));

#define SOH 0x01
#define STX 0x02
#define EOT 0x04
#define ACK 0x06
#define NAK 0x15
#define CPMEOF 0x1A

#endif
