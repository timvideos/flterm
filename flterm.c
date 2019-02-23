/*
 * flterm
 * Copyright (C) 2019 Ewen McNeill
 * Copyright (C) 2017 Tim 'mithro' Ansell
 * Copyright (C) 2007, 2008, 2009, 2010, 2011 Sebastien Bourdeauducq
 * Copyright (C) 2011 Michael Walle
 * Copyright (C) 2004 MontaVista Software, Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <sfl.h>
#include <xmodem.h>

#ifdef __linux__
#include <linux/serial.h>
#endif

#define DEFAULT_KERNELADR	(0x40000000)
#define DEFAULT_CMDLINEADR	(0x41000000)
#define DEFAULT_INITRDADR	(0x41002000)

#define GDBBUFLEN 1000

enum line_end {
	// cr - \r - Carriage return
	// nl - \n - Newline
	LINE_END_PASS,    // pass    - don't touch line endings
	LINE_END_CR2,     // igncr   - ignore carriage return
	LINE_END_CR2NL,   // cr2nl   - translate carriage return to newline
	LINE_END_NL2,	  // ignnl   - ignore newline
	LINE_END_NL2CR,   // nl2cr   - translate newline to carriage return
	LINE_END_NL2CRNL, // nl2crnl - translate carriage return and then newline
};

unsigned int crc16_table[256] = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
	0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
	0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
	0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
	0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
	0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
	0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
	0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
	0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
	0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
	0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
	0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
	0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
	0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
	0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
	0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
	0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
	0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
	0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
	0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
	0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
	0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
	0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

static int debug = 0;

static bool run_terminal = true;

static unsigned short crc16(const void *_buffer, int len)
{
	const unsigned char *buffer = (const unsigned char *)_buffer;
	unsigned short crc;

	crc = 0;
	while(len-- > 0)
	    crc = crc16_table[((crc >> 8) ^ (*buffer++)) & 0xFF] ^ (crc << 8);

	return crc;
}

/** \brief Calculate XMODEM CRC16

The XMODEM CRC16 is different from the CRC16 used in SFL, and thus requires
a separate function. The XMODEM CRC16 is a variant of the CCITT CRC16:
http://reveng.sourceforge.net/crc-catalogue/16.htm#crc.cat-bits.16

\param [in] data Array of data to calculate CRC16.
\param [in] size Size of input array.
*/
unsigned short xmodem_crc16(unsigned char * data, size_t size)
{
	const unsigned int crc_poly = 0x1021;
	unsigned int crc = 0x0000;

	unsigned int octet_count;
	unsigned char bit_count;
	for(octet_count = 0; octet_count < size; octet_count++) {
		crc = (crc ^ (unsigned int) (data[octet_count] & (0xFF)) << 8);
		for(bit_count = 1; bit_count <= 8; bit_count++) {
			if(crc & 0x8000) {
				crc = (crc << 1) ^ crc_poly;
			} else	{
				crc <<= 1;
			}
		}
	}
	return crc;
}

static int write_exact(int fd, const char *data, unsigned int length)
{
	int r;

	while(length > 0) {
		r = write(fd, data, length);
		if(r <= 0) return 0;
		length -= r;
		data += r;
	}
	return 1;
}

/* length, cmd and payload must be filled in */
static int send_frame(int serialfd, struct sfl_frame *frame)
{
	unsigned short int crc;
	int retry;
	char reply;

	crc = crc16(&frame->cmd, frame->length+1);
	frame->crc[0] = (crc & 0xff00) >> 8;
	frame->crc[1] = (crc & 0x00ff);

	retry = 0;
	do {
		if(!write_exact(serialfd, (char *)frame, frame->length+4)) {
			perror("[FLTERM] Unable to write to serial port.");
			return 0;
		}
		/* Get the reply from the device */
		read(serialfd, &reply, 1); /* TODO: timeout */
		switch(reply) {
			case SFL_ACK_SUCCESS:
				retry = 0;
				break;
			case SFL_ACK_CRCERROR:
				retry = 1;
				break;
			default:
				fprintf(stderr, "[FLTERM] Got unknown reply '%c' from the device, aborting.\n", reply);
				return 0;
		}
	} while(retry);
	return 1;
}

static int upload_fd(int serialfd, const char *name, int firmwarefd, unsigned int load_address)
{
	struct sfl_frame frame;
	int readbytes;
	int length;
	int position;
	unsigned int current_address;
	struct timeval t0;
	struct timeval t1;
	int millisecs;

	length = lseek(firmwarefd, 0, SEEK_END);
	lseek(firmwarefd, 0, SEEK_SET);

	printf("[FLTERM] Uploading %s (%d bytes)...\n", name, length);

	gettimeofday(&t0, NULL);

	current_address = load_address;
	position = 0;
	while(1) {
		printf("%d%%\r", 100*position/length);
		fflush(stdout);

		readbytes = read(firmwarefd, &frame.payload[4], sizeof(frame.payload) - 4);
		if(readbytes < 0) {
			perror("[FLTERM] Unable to read image.");
			return -1;
		}
		if(readbytes == 0) break;

		frame.length = readbytes+4;
		frame.cmd = SFL_CMD_LOAD;
		frame.payload[0] = (current_address & 0xff000000) >> 24;
		frame.payload[1] = (current_address & 0x00ff0000) >> 16;
		frame.payload[2] = (current_address & 0x0000ff00) >> 8;
		frame.payload[3] = (current_address & 0x000000ff);

		if(!send_frame(serialfd, &frame)) return -1;

		current_address += readbytes;
		position += readbytes;
	}

	gettimeofday(&t1, NULL);

	millisecs = (t1.tv_sec - t0.tv_sec)*1000 + (t1.tv_usec - t0.tv_usec)/1000;

	printf("[FLTERM] Upload complete (%.1fKB/s).\n", 1000.0*(double)length/((double)millisecs*1024.0));
	return length;
}

/** \brief XMODEM transmitter implementation

This XMODEM transmitter only sends 1k packets for simplicity of implementation.
It is up to the user to ensure the receiver. Additionally, because XMODEM only
transmits in multiples of 128 or 1024 (the latter only this case), this
transmitter expects the receiver to strip trailing padding bytes when the final
packet is sent. In other words, the receiver should already be file-size aware.

\param [in] serialfd File descriptor for serial connection.
\param [in] name Name of file to print to stdout.
\param [in] firmwarefd File descriptor of file to send.
*/
static int upload_xmodem(int serialfd, const char *name, int firmwarefd)
{
	struct xmodem_packet packet;
	unsigned char curr_packet = 1;
	int less_than_1k = 0;
	int firmware_pos = 0;
	int err_count = 0;
	int done = 0;
	int length;
	struct timeval t0;
	struct timeval t1;
	int millisecs;


	length = lseek(firmwarefd, 0, SEEK_END);
	lseek(firmwarefd, 0, SEEK_SET);

	printf("[FLTERM] Uploading %s (%d bytes)...\n", name, length);

	gettimeofday(&t0, NULL);

	// Abbreviated XMODEM transmitter- only sends 1024 byte packets.
	while(!done) {
		char reply;
		int readbytes;
		unsigned short crc;

		printf("%d%%\r", 100*firmware_pos/length);
		fflush(stdout);

		packet.start = less_than_1k ? SOH : STX;
		packet.num = curr_packet;
		packet.num_comp = ~packet.num;

		readbytes = read(firmwarefd, &packet.payload, 1024);
		if(readbytes < 0) {
			perror("[FLTERM] Unable to read image.");
			return -1;
		}

		// Pad final packet per XMODEM spec.
		if(readbytes < sizeof(packet.payload)) {
			done = 1;
			memset(&packet.payload[0] + readbytes, CPMEOF, 1024 - readbytes);
		}

		crc = xmodem_crc16(packet.payload, 1024);
		packet.crc[0] = (crc & 0xff00) >> 8;
		packet.crc[1] = (crc & 0x00ff);

		if(!write_exact(serialfd, (char *) &packet, 1029)) {
			perror("[FLTERM] Unable to write to serial port.");
			return 0;
		}

		read(serialfd, &reply, 1);

		if(reply == ACK) {
			if(!done) {
				curr_packet++;
				firmware_pos += 1024;
				err_count = 0;
			}
		} else {
			if(err_count < 11) {
				lseek(firmwarefd, firmware_pos, SEEK_SET);
				done = 0; // Last packet may need to be resent.
				err_count++;
			} else {
				perror("[FLTERM] Error count exceeded while transmitting. Aborting.");
				return 0;
			}
		}
	}

	{
		const char eot = EOT;
		char last_reply;
		write_exact(serialfd, &eot, 1);
		read(serialfd, &last_reply, 1);

		if(last_reply != ACK) {
			perror("[FLTERM] Sent EOT, but did not receive ACK. Aborting.");
			return 0;
		}
	}

	gettimeofday(&t1, NULL);
	millisecs = (t1.tv_sec - t0.tv_sec)*1000 + (t1.tv_usec - t0.tv_usec)/1000;

	printf("[FLTERM] Upload complete (%.1fKB/s).\n", 1000.0*(double)length/((double)millisecs*1024.0));
	return length;
}

static const char sfl_magic_req[SFL_MAGIC_LEN] = SFL_MAGIC_REQ;
static const char sfl_magic_ack[SFL_MAGIC_LEN] = SFL_MAGIC_ACK;

static void answer_magic(int serialfd,
	const char *kernel_image, unsigned int kernel_address,
	const char *cmdline, unsigned int cmdline_address,
	const char *initrd_image, unsigned int initrd_address)
{
	int kernelfd, initrdfd;
	struct sfl_frame frame;

	printf("[FLTERM] Received firmware download request from the device.\n");

	kernelfd = open(kernel_image, O_RDONLY);
	if(kernelfd == -1) {
		perror("[FLTERM] Unable to open kernel image (request ignored).");
		return;
	}
	initrdfd = -1;
	if(initrd_image != NULL) {
		initrdfd = open(initrd_image, O_RDONLY);
		if(initrdfd == -1) {
			perror("[FLTERM] Unable to open initrd image (request ignored).");
			close(kernelfd);
			return;
		}
	}

	write_exact(serialfd, sfl_magic_ack, SFL_MAGIC_LEN);

	upload_fd(serialfd, "kernel", kernelfd, kernel_address);
	if(cmdline != NULL) {
		int len;

		printf("[FLTERM] Setting kernel command line: '%s'.\n", cmdline);

		len = strlen(cmdline)+1;
		if(len > (254-4)) {
			fprintf(stderr, "[FLTERM] Kernel command line too long, load aborted.\n");
			close(initrdfd);
			close(kernelfd);
			return;
		}
		frame.length = len+4;
		frame.cmd = SFL_CMD_LOAD;
		frame.payload[0] = (cmdline_address & 0xff000000) >> 24;
		frame.payload[1] = (cmdline_address & 0x00ff0000) >> 16;
		frame.payload[2] = (cmdline_address & 0x0000ff00) >> 8;
		frame.payload[3] = (cmdline_address & 0x000000ff);
		strcpy((char *)&frame.payload[4], cmdline);
		send_frame(serialfd, &frame);

		frame.length = 4;
		frame.cmd = SFL_CMD_CMDLINE;
		frame.payload[0] = (cmdline_address & 0xff000000) >> 24;
		frame.payload[1] = (cmdline_address & 0x00ff0000) >> 16;
		frame.payload[2] = (cmdline_address & 0x0000ff00) >> 8;
		frame.payload[3] = (cmdline_address & 0x000000ff);
		send_frame(serialfd, &frame);
	}
	if(initrdfd != -1) {
		int len;

		len = upload_fd(serialfd, "initrd", initrdfd, initrd_address);
		if(len <= 0) return;

		frame.length = 4;
		frame.cmd = SFL_CMD_INITRDSTART;
		frame.payload[0] = (initrd_address & 0xff000000) >> 24;
		frame.payload[1] = (initrd_address & 0x00ff0000) >> 16;
		frame.payload[2] = (initrd_address & 0x0000ff00) >> 8;
		frame.payload[3] = (initrd_address & 0x000000ff);
		send_frame(serialfd, &frame);

		initrd_address += len-1;

		frame.length = 4;
		frame.cmd = SFL_CMD_INITRDEND;
		frame.payload[0] = (initrd_address & 0xff000000) >> 24;
		frame.payload[1] = (initrd_address & 0x00ff0000) >> 16;
		frame.payload[2] = (initrd_address & 0x0000ff00) >> 8;
		frame.payload[3] = (initrd_address & 0x000000ff);
		send_frame(serialfd, &frame);
	}

	/* Send the jump command */
	printf("[FLTERM] Booting the device.\n");
	frame.length = 4;
	frame.cmd = SFL_CMD_JUMP;
	frame.payload[0] = (kernel_address & 0xff000000) >> 24;
	frame.payload[1] = (kernel_address & 0x00ff0000) >> 16;
	frame.payload[2] = (kernel_address & 0x0000ff00) >> 8;
	frame.payload[3] = (kernel_address & 0x000000ff);
	if(!send_frame(serialfd, &frame)) return;

	printf("[FLTERM] Done.\n");

	close(initrdfd);
	close(kernelfd);
}

/** \brief Transfer file using XMODEM protocol

If flterm was started with the `--kernel` option, upon receiving an ASCII_C
character, `flterm` will begin an XMODEM protcol style transfer to the
remote target using 1k packets. It is up to the user to ensure the receiver
is ready for an XMODEM transfer and can handle 1k packets. Because XMODEM
does not specify an remote address within the protocol, the `--kernel-address`
option is ignored for this protocol; the receiver should know what to do with
the sent file.

Unlike the SFL protocol, which sends _and_ expects a magic string that a user
is unlikely to type in practice, the starting character for an XMODEM transfer
is very common (ASCII 'C'). To prevent spurious transfers from initiating,
only one XMODEM transfer can be started for each flterm spawned. If another
file needs to be sent, a user should initiate a transfer on the receiver side
and restart `flterm`.

\param [in] serialfd File descriptor for serial connection.
\param [in] kernel_image File name of file to open an send.
*/
static void answer_xmodem(int serialfd, const char *kernel_image)
{
	int kernelfd;

	printf("[FLTERM] Received XMODEM start char ('C'); xmodem option and kernel image specified.\n");

	kernelfd = open(kernel_image, O_RDONLY);
	if(kernelfd == -1) {
		perror("[FLTERM] Unable to open kernel image (request ignored).");
		return;
	}

	upload_xmodem(serialfd, "kernel", kernelfd);

	printf("[FLTERM] Done. To do another XMODEM xfer, respawn flterm.\n");

	close(kernelfd);
}

static int hex(unsigned char c)
{
	if(c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if(c >= '0' && c <= '9') {
		return c - '0';
	}
	if(c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return 0;
}

/*
 * This is taken from kdmx2.
 * Author: Tom Rini <trini@mvista.com>
 */
static void gdb_process_packet(int infd, int outfd, int altfd)
{
	/* gdb packet handling */
	char gdbbuf[GDBBUFLEN + 1];
	int pos = 0;
	unsigned char runcksum = 0;
	unsigned char recvcksum = 0;
	struct pollfd fds;
	char c;
	int seen_hash = 0;

	fds.fd = infd;
	fds.events = POLLIN;

	memset(gdbbuf, 0, sizeof(gdbbuf));
	gdbbuf[0] = '$';
	pos++;

	while (1) {
		fds.revents = 0;
		if(poll(&fds, 1, 100) == 0) {
			/* timeout */
			if(altfd != -1) {
				write(altfd, gdbbuf, pos);
			}
			break;
		}
		if(pos == GDBBUFLEN) {
			if(altfd != -1) {
				write(altfd, gdbbuf, pos);
			}
			break;
		}
		read(infd, &c, 1);
		gdbbuf[pos++] = c;
		if(c == '#') {
			seen_hash = 1;
		} else if(seen_hash == 0) {
			runcksum += c;
		} else if(seen_hash == 1) {
			recvcksum = hex(c) << 4;
			seen_hash = 2;
		} else if(seen_hash == 2) {
			recvcksum |= hex(c);
			seen_hash = 3;
		}

		if(seen_hash == 3) {
			/* we're done */
			runcksum %= 256;
			if(recvcksum == runcksum) {
				if(debug) {
					fprintf(stderr, "[GDB %s]\n", gdbbuf);
				}
				write(outfd, gdbbuf, pos);
			} else {
				if(altfd != -1) {
					write(altfd, gdbbuf, pos);
				}
			}
			seen_hash = 0;
			break;
		}
	}
}

/*
 * Manually translate line endings when transmitting down the serial port.
 */
static int write_text(int serialfd, char c, enum line_end line_end) {
	if (c == '\r') {
		switch(line_end) {
			case LINE_END_CR2:
				return 1;
			case LINE_END_CR2NL:
				c = '\n';
				break;
			default:
				break;
		}
	}
	if (c == '\n') {
		switch(line_end) {
			case LINE_END_NL2:
				return 1;
			case LINE_END_NL2CR:
				c = '\r';
				break;
			case LINE_END_NL2CRNL: {
				char c2 = '\r';
				int ret = write(serialfd, &c2, 1);
				if(ret <= 0) return ret;
			}
			default:
				break;
		}
	}
	return write(serialfd, &c, 1);
}

static void handle_sigint(int _sig)
{
	/* Indicate do_terminal() should exit, install default handler again */
	run_terminal = false;
	signal(SIGINT, SIG_DFL);
}

static void do_terminal(
	char *serial_port, int baud, enum line_end line_end,
	int gdb_passthrough, int allow_xmodem,
	const char *kernel_image, unsigned int kernel_address,
	const char *cmdline, unsigned int cmdline_address,
	const char *initrd_image, unsigned int initrd_address,
	char *log_path)
{
	int first_xstart = 1; /* XMODEM should only run once, and only if kernel
						   * and xmodem options were supplied. */
	int serialfd;
	int gdbfd = -1;
	FILE *logfd = NULL;
	struct termios my_termios;
	char c;
	int recognized;
	struct pollfd fds[3];
	int flags;
	int rsp_pending = 0;
	int c_cflag;
	int custom_divisor;

	/* Install signal handler, so that we exit cleanly on ctrl-c */
	run_terminal = true;
	(void)signal(SIGINT, handle_sigint);

	/* Open and configure the serial port */
	if(log_path != NULL) {
		logfd = fopen(log_path, "a+");
		if(logfd == NULL) {
			perror("Unable to open log file");
			return;
		}
	}

	serialfd = open(serial_port, O_RDWR|O_NOCTTY);
	if(serialfd == -1) {
		perror("Unable to open serial port");
		return;
	}

	custom_divisor = 0;
	switch(baud) {
		case 9600: c_cflag = B9600; break;
		case 19200: c_cflag = B19200; break;
		case 38400: c_cflag = B38400; break;
		case 57600: c_cflag = B57600; break;
		case 115200: c_cflag = B115200; break;
		case 230400: c_cflag = B230400; break;
		default:
			c_cflag = B115200;
			custom_divisor = 1;
			break;
	}

#ifdef __linux__
	if(custom_divisor) {
		struct serial_struct serial_info;
		ioctl(serialfd, TIOCGSERIAL, &serial_info);
		serial_info.custom_divisor = serial_info.baud_base / baud;
		serial_info.flags &= ~ASYNC_SPD_MASK;
		serial_info.flags |= ASYNC_SPD_CUST;
		ioctl(serialfd, TIOCSSERIAL, &serial_info);
	}
#else
	if(custom_divisor) {
		fprintf(stderr, "[FLTERM] baudrate not supported\n");
		return;
	}
#endif

	/* Thanks to Julien Schmitt (GTKTerm) for figuring out the correct parameters
	 * to put into that weird struct.
	 */
	tcgetattr(serialfd, &my_termios);
	my_termios.c_cflag = c_cflag;
	my_termios.c_cflag |= CS8;
	my_termios.c_cflag |= CREAD;
	my_termios.c_iflag = IGNPAR | IGNBRK;
	my_termios.c_cflag |= CLOCAL;
	my_termios.c_oflag = 0;
	my_termios.c_lflag = 0;
	my_termios.c_cc[VTIME] = 0;
	my_termios.c_cc[VMIN] = 1;
	tcsetattr(serialfd, TCSANOW, &my_termios);
	tcflush(serialfd, TCOFLUSH);
	tcflush(serialfd, TCIFLUSH);

	/* Prepare the fdset for poll()
	 * fd[0] == stdin
	 * fd[1] == serial port
	 * fd[2] == gdb passthrough
	 */
	fds[0].fd = 0;
	fds[0].events = POLLIN;
	fds[1].fd = serialfd;
	fds[1].events = POLLIN;

	recognized = 0;
	flags = fcntl(serialfd, F_GETFL, 0);
	while(run_terminal) {
		if(gdbfd == -1 && gdb_passthrough) {
			gdbfd = open("/dev/ptmx", O_RDWR);
			if(grantpt(gdbfd) != 0) {
				perror("grantpt()");
				return;
			}
			if(unlockpt(gdbfd) != 0) {
				perror("unlockpt()");
				return;
			}
			printf("[GDB passthrough] use %s as GDB remote device\n",
					ptsname(gdbfd));
			fds[2].fd = gdbfd;
			fds[2].events = POLLIN;
		}

		fds[0].revents = 0;
		fds[1].revents = 0;
		fds[2].revents = 0;

		/* poll() behaves strangely when the serial port descriptor is in
		 * blocking mode. So work around this.
		 */
		fcntl(serialfd, F_SETFL, flags|O_NONBLOCK);
		if(poll(&fds[0], (gdbfd == -1) ? 2 : 3, -1) < 0) break;
		fcntl(serialfd, F_SETFL, flags);

		/* Data from stdin */
		if(fds[0].revents & POLLIN) {
			if(read(0, &c, 1) <= 0) break;
			if(c=='\04') {
				/* exit on ^d */
				run_terminal = false;
				break;
			}
			if(write_text(serialfd, c, line_end) <= 0) break;
		}

		/* Data from gdb passthrough. */
		if(fds[2].revents & POLLIN) {
			rsp_pending = 1;
			if(read(gdbfd, &c, 1) <= 0) break;
			if(c == '\03') {
				/* convert ETX to breaks */
				if(debug) {
					fprintf(stderr, "[GDB BREAK]\n");
				}
				tcsendbreak(serialfd, 0);
			} else if(c == '$') {
				gdb_process_packet(gdbfd, serialfd, -1);
			} else if(c == '+' || c == '-') {
				write(serialfd, &c, 1);
			} else {
				fprintf(stderr, "Internal error (line %d)", __LINE__);
				exit(1);
			}
		}

		/* Signal from gdb passthrough. */
		if(fds[2].revents & POLLHUP) {
			/* close and reopen new pair */
			close(gdbfd);
			gdbfd = -1;
			continue;
		}

		/* Data from serial port. */
		if(fds[1].revents & POLLIN) {
			if(read(serialfd, &c, 1) <= 0) break;

			if(logfd && c && isascii(c)) {
				fwrite(&c, sizeof(c), 1, logfd);
				if(c == '\n') fflush(logfd);
			}

			if(gdbfd != -1 && rsp_pending && (c == '+' || c == '-')) {
				rsp_pending = 0;
				write(gdbfd, &c, 1);
			} else if(gdbfd != -1 && c == '$') {
				gdb_process_packet(serialfd, gdbfd, 0);
			} else {
				/* write to terminal */
				write(0, &c, 1);

				if(kernel_image != NULL) {
					if(c == sfl_magic_req[recognized]) {
						recognized++;
						if(recognized == SFL_MAGIC_LEN) {
							/* We've got the magic string ! */
							recognized = 0;
							answer_magic(serialfd,
								kernel_image, kernel_address,
								cmdline, cmdline_address,
								initrd_image, initrd_address);
						}
					} else if(c != 'C') {
						/* If XMODEM start not detected, continue looking
						 * for SFL start.
						 */
						if(c == sfl_magic_req[0]) recognized = 1; else recognized = 0;
					} else {
						/* XMODEM detected */
						if(first_xstart && allow_xmodem) {
							answer_xmodem(serialfd, kernel_image);
							first_xstart = 0;
						}
					}
				}
			}
		}
	}

	signal(SIGINT, SIG_DFL);
	close(serialfd);

	if(gdbfd != -1) close(gdbfd);
	if(logfd) fclose(logfd);
}

enum {
	OPTION_PORT,
	OPTION_GDB_PASSTHROUGH,
	OPTION_SPEED,
	OPTION_DEBUG,
	OPTION_KERNEL,
	OPTION_KERNELADR,
	OPTION_CMDLINE,
	OPTION_CMDLINEADR,
	OPTION_INITRD,
	OPTION_INITRDADR,
	OPTION_LOG,
	OPTION_HELP,
	OPTION_LINEENDINGS,
	OPTION_XMODEM,
};

static const struct option options[] = {
	{
		.name = "port",
		.has_arg = 1,
		.val = OPTION_PORT
	},
	{
		.name = "gdb-passthrough",
		.has_arg = 0,
		.val = OPTION_GDB_PASSTHROUGH
	},
	{
		.name = "xmodem",
		.has_arg = 0,
		.val = OPTION_XMODEM
	},
	{
		.name = "debug",
		.has_arg = 0,
		.val = OPTION_DEBUG
	},
	{
		.name = "speed",
		.has_arg = 1,
		.val = OPTION_SPEED
	},
	{
		.name = "kernel",
		.has_arg = 1,
		.val = OPTION_KERNEL
	},
	{
		.name = "kernel-adr",
		.has_arg = 1,
		.val = OPTION_KERNELADR
	},
	{
		.name = "cmdline",
		.has_arg = 1,
		.val = OPTION_CMDLINE
	},
	{
		.name = "cmdline-address",
		.has_arg = 1,
		.val = OPTION_CMDLINEADR
	},
	{
		.name = "initrd",
		.has_arg = 1,
		.val = OPTION_INITRD
	},
	{
		.name = "initrd-adr",
		.has_arg = 1,
		.val = OPTION_INITRDADR
	},
	{
		.name = "log",
		.has_arg = 1,
		.val = OPTION_LOG
	},
	{
		.name = "help",
		.has_arg = 0,
		.val = OPTION_HELP
	},
	/* Helpful aliases for addr */
	{
		.name = "kernel-addr",
		.has_arg = 1,
		.val = OPTION_KERNELADR
	},
	{
		.name = "kernel-address",
		.has_arg = 1,
		.val = OPTION_KERNELADR
	},
	{
		.name = "cmdline-adr",
		.has_arg = 1,
		.val = OPTION_CMDLINEADR
	},
	{
		.name = "cmdline-addr",
		.has_arg = 1,
		.val = OPTION_CMDLINEADR
	},
	{
		.name = "initrd-addr",
		.has_arg = 1,
		.val = OPTION_INITRDADR
	},
	{
		.name = "initrd-address",
		.has_arg = 1,
		.val = OPTION_INITRDADR
	},
	/* Also allow --baud */
	{
		.name = "baud",
		.has_arg = 1,
		.val = OPTION_SPEED
	},
	{
		.name = "line-endings",
		.has_arg = 1,
		.val = OPTION_LINEENDINGS,
	},
	{
		.name = NULL
	}
};

static void print_usage()
{
	fprintf(stderr, "Serial boot program for MiSoC & LiteX - " GIT_VERSION "\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "This program is free software: you can redistribute it and/or modify\n");
	fprintf(stderr, "it under the terms of the GNU General Public License as published by\n");
	fprintf(stderr, "the Free Software Foundation, version 3 of the License.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Usage: flterm --port <port>\n");
	fprintf(stderr, "              [--speed <speed>] [--line-endings <mode>]\n");
	fprintf(stderr, "              [--gdb-passthrough] [--xmodem] [--debug]\n");
	fprintf(stderr, "              [--kernel <kernel_image> [--kernel-adr <address>]]\n");
	fprintf(stderr, "              [--cmdline <cmdline> [--cmdline-adr <address>]]\n");
	fprintf(stderr, "              [--initrd <initrd_image> [--initrd-adr <address>]]\n");
	fprintf(stderr, "              [--log <log_file>]\n\n");
	fprintf(stderr, "Default load addresses:\n");
	fprintf(stderr, "  kernel:  0x%08x\n", DEFAULT_KERNELADR);
	fprintf(stderr, "  cmdline: 0x%08x\n", DEFAULT_CMDLINEADR);
	fprintf(stderr, "  initrd:  0x%08x\n", DEFAULT_INITRDADR);
	fprintf(stderr, "\n");
	fprintf(stderr, "flterm can optional translate line endings going out the serial port\n");
	fprintf(stderr, "using the --line-endings option. Valid values are:\n");
	fprintf(stderr, " pass    - don't change line endings\n");
	fprintf(stderr, " igncr   - ignore carriage return\n");
	fprintf(stderr, " cr2nl   - translate carriage return to newline\n");
	fprintf(stderr, " ignnl   - ignore newline\n");
	fprintf(stderr, " nl2cr   - translate newline to carriage return\n");
	fprintf(stderr, " nl2crnl - translate newline to carriage return then newline (default)\n");
}

int main(int argc, char *argv[])
{
	int opt;
	char *serial_port;
	int baud;
	enum line_end line_end = LINE_END_NL2CRNL;
	int gdb_passthrough;
	int allow_xmodem;
	char *kernel_image;
	unsigned int kernel_address;
	char *cmdline;
	unsigned int cmdline_address;
	char *initrd_image;
	unsigned int initrd_address;
	char *endptr;
	char *log_path;
	struct termios otty, ntty;

	/* Fetch command line arguments */
	serial_port = NULL;
	baud = 115200;
	gdb_passthrough = 0;
	allow_xmodem = 0;
	kernel_image = NULL;
	kernel_address = DEFAULT_KERNELADR;
	cmdline = NULL;
	cmdline_address = DEFAULT_CMDLINEADR;
	initrd_image = NULL;
	initrd_address = DEFAULT_INITRDADR;
	log_path = NULL;
	while((opt = getopt_long(argc, argv, "", options, NULL)) != -1) {
		if(opt == '?') {
			print_usage();
			return 1;
		}
		switch(opt) {
			case OPTION_PORT:
				free(serial_port);
				serial_port = strdup(optarg);
				break;
			case OPTION_SPEED:
				baud = strtoul(optarg, &endptr, 0);
				if(*endptr != 0) {
					fprintf(stderr, "[FLTERM] Couldn't parse baudrate\n");
					return 1;
				}
				break;
			case OPTION_DEBUG:
				debug = 1;
				break;
			case OPTION_GDB_PASSTHROUGH:
				gdb_passthrough = 1;
				break;
			case OPTION_XMODEM:
				allow_xmodem = 1;
				break;
			case OPTION_KERNEL:
				free(kernel_image);
				kernel_image = strdup(optarg);
				break;
			case OPTION_KERNELADR:
				kernel_address = strtoul(optarg, &endptr, 0);
				if(*endptr != 0) {
					fprintf(stderr, "[FLTERM] Couldn't parse kernel address\n");
					return 1;
				}
				break;
			case OPTION_CMDLINE:
				free(cmdline);
				cmdline = strdup(optarg);
				break;
			case OPTION_CMDLINEADR:
				cmdline_address = strtoul(optarg, &endptr, 0);
				if(*endptr != 0) {
					fprintf(stderr, "[FLTERM] Couldn't parse cmdline address\n");
					return 1;
				}
				break;
			case OPTION_INITRD:
				free(initrd_image);
				initrd_image = strdup(optarg);
				break;
			case OPTION_INITRDADR:
				initrd_address = strtoul(optarg, &endptr, 0);
				if(*endptr != 0) {
					fprintf(stderr, "[FLTERM] Couldn't parse initrd address\n");
					return 1;
				}
				break;
			case OPTION_LOG:
				free(log_path);
				log_path = strdup(optarg);
				break;
			case OPTION_HELP:
				print_usage();
				return 0;
			case OPTION_LINEENDINGS:
				if (false) {
				} else 	if (strcasecmp(optarg, "pass") == 0) {
					line_end = LINE_END_PASS;
				} else 	if (strcasecmp(optarg, "igncr") == 0) {
					line_end = LINE_END_CR2;
				} else 	if (strcasecmp(optarg, "cr2nl") == 0) {
					line_end = LINE_END_CR2NL;
				} else 	if (strcasecmp(optarg, "ignnl") == 0) {
					line_end = LINE_END_NL2;
				} else 	if (strcasecmp(optarg, "nl2cr") == 0) {
					line_end = LINE_END_NL2CR;
				} else 	if (strcasecmp(optarg, "nl2crnl") == 0) {
					line_end = LINE_END_NL2CRNL;
				} else {
					fprintf(stderr, "[FLTERM] Couldn't parse line-ending argument\n");
					return 1;
				}
				break;
		}
	}

	if(serial_port == NULL) {
		fprintf(stderr, "[FLTERM] No port given\n");
		return 1;
	}

	/* Banner */
	printf("[FLTERM] " GIT_VERSION " Starting...\n");
	/* Set up stdin/out */
	tcgetattr(0, &otty);
	ntty = otty;
	ntty.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(0, TCSANOW, &ntty);

	/* Do the bulk of the work */
	do_terminal(
		serial_port, baud, line_end,
		gdb_passthrough, allow_xmodem,
		kernel_image, kernel_address,
		cmdline, cmdline_address,
		initrd_image, initrd_address,
		log_path);

	/* Restore stdin/out into their previous state */
	tcsetattr(0, TCSANOW, &otty);

	printf("\n[FLTERM] Exiting...\n");

	return 0;
}
