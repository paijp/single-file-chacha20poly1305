
/*
	Single file chacha20poly1305 https://github.com/paijp/single-file-chacha20poly1305
	
	License: MIT or PUBLIC DOMAIN.
*/

/*jp.pa-i.cir/map32mx2-28
LSS	RPB3
LRS_T2P	RPB4
P2L_P2T	RPB5	SDO1
LCK_TCK	RPB14	SCK1
PGD	RPB10	PGED2	UTX2
PGC	RPB11	PGDC2
fix	CLKI	CLKO	VCAP
VBUS	RB6
VUSB3V3	RB12

P1	RPB8
P2	RPA0
P3	RPA1
P4	RPB0
P5	RPB1
P6	RPB2
P7__P2W	RPB15	UTX1
P8__W2P	RPB13	URX1
P9__SCL	RPA4
P10	RPB9	UTX2
P19__TSS_SDA	RPB7

*/


#include	<xc.h>
#include	"tplib.h"

#include	"c20p1305.h"
#include	"i2c.h"


static	UB	c20p1305key[32] = {0};
static	UB	c20p1305nonce[12] = {0};
static	UW	c20p1305nvcounter = 0;
static	UW	c20p1305vcounter = 0;


static	W	c4wroom(W tmout)
{
	W	c;
	
	if (tmout > 0) {
		TMR2 = 0;
		IFS0bits.T2IF = 0;
	}
	for (;;) {
		if ((U1STAbits.OERR))
			U1STA = 0x1400;
		if ((U1STAbits.URXDA)) {
			c = U1RXREG;
			return c;
		}
		if (tmout == 0)
			return -1;
		if ((tmout > 0)&&(IFS0bits.T2IF)) {
			IFS0bits.T2IF = 0;
			tmout--;
		}
	}
}


static	void	wroom4c(UB c)
{
	do {
		if ((U1STAbits.OERR))
			U1STA = 0x1400;
	} while ((U1STAbits.UTXBF));
	U1TXREG = c;
}


static	W	wroom4cmd(const UB *send, const UB *recv, W tmout)
{
	W	c;
	const	UB	*p;
	
	lcdtp_sendlogs("\nwroom<");
	lcdtp_sendlogs(send);
	
	while ((U1STAbits.URXDA)) {
		if ((U1STAbits.OERR))
			U1STA = 0x1400;
		c = U1RXREG;
	}
	
	p = send;
	while ((c = *(p++)))
		wroom4c(c);
	
	if (recv == NULL)
		return 0;
	lcdtp_sendlogs("wroom>");
	p = recv;
	TMR2 = 0;
	IFS0bits.T2IF = 0;
	for (;;) {
		if ((IFS0bits.T2IF)) {
			IFS0bits.T2IF = 0;
			if (tmout > 0)
				tmout--;
		}
		if ((c = c4wroom(0)) < 0) {
			if (tmout == 0)
				return -1;
			continue;
		}
		lcdtp_sendlogc(c);
		if (c != *p) {
			p = recv;
			continue;
		}
		if (*(++p) == 0)
			break;
	}
	lcdtp_sendlogs("\n");
	return 0;
}


static	W	wroom4ub(W c)
{
	static	const	UB	*bin2hex = "0123456789abcdef";
	
#if 1
	static	UB	s[3] = {'0', '0', 0};
	
	s[0] = bin2hex[(c >> 4) & 0xf];
	s[1] = bin2hex[c & 0xf];
	wroom4cmd(s, NULL, -1);
#else
	wroom4c(bin2hex[(c >> 4) & 0xf]);
	wroom4c(bin2hex[c & 0xf]);
#endif
	return 1;
}


static	W	count4page(W page)
{
	W	v0, v1, v2, v3;
	
	i2cstop();
	i2cstart();
	if ((i2csend(0x50 * 2))) {
		i2cstop();
		return -1;
	}
	i2csend(page);
	i2csend(0);
	i2cstop();
	
	i2cstart();
	i2csend(0x50 * 2 + 1);
	v0 = i2crecv(0);
	v1 = i2crecv(0);
	v2 = i2crecv(0);
	v3 = i2crecv(1);
	i2cstop();
	
	if ((v0 ^ v2) != 0xff)
		return -1;
	if ((v1 ^ v3) != 0xff)
		return -1;
	return (v0 << 8) | v1;
}


static	W	writecount4page(W page, W v)
{
	i2cstop();
	i2cstart();
	if ((i2csend(0x50 * 2))) {
		i2cstop();
		return -1;
	}
	i2csend(page);
	i2csend(0);
	i2csend((v >> 8) & 0xff);
	i2csend(v & 0xff);
	i2csend(((v >> 8) & 0xff) ^ 0xff);
	i2csend((v & 0xff) ^ 0xff);
	i2cstop();
	
	do {
		i2cstop();
		i2cstart();
	} while ((i2csend(0x50 * 2)));
	i2cstop();
	return 0;
}


int	main(int ac, char **av)
{
	static	W	count0 = 0;
	static	W	val0 = 0;
	static	W	val1 = 0;
	static	W	group = 0;
	static	W	groupa = 0;
	static	W	volume0 = 0;
	static	struct	tplib_parts_struct	parts[] = {
		{tplib_parts_fill, 0, 0, LCD_W, LCD_H, 0x0000, NULL, NULL, NULL, 0}, 
		{tplib_parts_log, 0, 0, LCD_W, LCD_H, 0, (char*)__func__, NULL, TPLIB_CONST2STR(SHA1SUM), 0}, 
		{tplib_parts_dec, 16, 16, 112, 24, 0, &val0, NULL, "val0:", 0}, 
		{tplib_parts_button, TPLIB_REL + 32, TPLIB_REL, 64, 32, 0, &val0, tplib_proc_tenkey, "set", 0}, 
		{tplib_parts_dec, 16, TPLIB_REL + 48, 112, 24, 0, &val1, NULL, "val1:", 0}, 
		{tplib_parts_button, TPLIB_REL + 32, TPLIB_REL, 64, 32, 0, &val1, tplib_proc_tenkey, "set", 0}, 
		{tplib_parts_buttonalt, 16, TPLIB_REL + 48, 64, 32, 0, NULL, NULL, "alt0", 0}, 
		{tplib_parts_buttonalt, TPLIB_REL + 80, TPLIB_REL, 64, 32, 1, NULL, NULL, "alt1", 0}, 
		{tplib_parts_buttongroup, 16, TPLIB_REL + 48, 64, 32, 0, &group, NULL, "group0", 0}, 
		{tplib_parts_buttongroup, TPLIB_REL + 8, TPLIB_REL, 64, 32, 1, &group, NULL, "group1", 0}, 
		{tplib_parts_buttongroup, TPLIB_REL + 8, TPLIB_REL, 64, 32, 2, &group, NULL, "group2", 0}, 
		{tplib_parts_buttongroup, 16, TPLIB_REL + 48, 64, 32, 0, &groupa, tplib_alwaysselect, "group0a", 0}, 
		{tplib_parts_buttongroup, TPLIB_REL + 8, TPLIB_REL, 64, 32, 1, &groupa, tplib_alwaysselect, "group1a", 0}, 
		{tplib_parts_buttongroup, TPLIB_REL + 8, TPLIB_REL, 64, 32, 2, &groupa, tplib_alwaysselect, "group2a", 0}, 
		{tplib_parts_dec, 16, TPLIB_REL + 48, 128, 24, 0, &volume0, NULL, "volume0:", 0}, 
		{tplib_parts_sliderv, TPLIB_REL + 16, TPLIB_REL, 32, 48, 0, &volume0, tplib_proc_redraw, NULL, 0}, 
		{NULL}
	};
	
	init_lcdtp();
	
	RPB15R = 1;		/* UTX1 */
	U1RXR = 3;		/* RPB13 */
	TRISBbits.TRISB13 = 1;
	CNPUBbits.CNPUB13 = 0;
	U1MODE = 0;
	U1BRG = (10000000 / 115200) - 1;
	U1MODE = 0x8008;		/* enable N81 4(U2BRG + 1) */
	U1STA = 0x1400;
	
	T2CON = 0x0070;		/* 1/256 */
	TMR2 = 0;
	PR2 = 156;		/* 40M / 256 / 1000Hz */
	T2CON = 0x8070;
	
	i2cstop();
	
	lcdtp_sendlogs("\nboot(" TPLIB_CONST2STR(SHA1SUM) ")\n");
	
	{
		W	i;
		
		for (i=0; i<0x80; i++) {
			if ((i & 7) == 0)
				lcdtp_sendlogub(i);
			i2cstart();
			if ((i2csend(i * 2 + 1)))
				lcdtp_sendlogs(" -");
			else
				lcdtp_sendlogs(" R");
			i2crecv(1);
			i2cstop();
			
			i2cstart();
			if ((i2csend(i * 2)))
				lcdtp_sendlogs("-");
			else
				lcdtp_sendlogs("W");
			i2cstop();
			if ((i & 7) == 7)
				lcdtp_sendlogs("\n");
		}
	}
	{
		W	i;
		
		if ((i = count4page(0)) >= 0)
			c20p1305nvcounter = i;
		lcdtp_sendloguw(i);
		lcdtp_sendlogs(":page0\n");
		if ((i = count4page(1)) >= 0)
			c20p1305nvcounter = i;
		lcdtp_sendloguw(i);
		lcdtp_sendlogs(":page1\n");
		
		writecount4page(0, c20p1305nvcounter + 1);
		writecount4page(1, c20p1305nvcounter + 1);
		lcdtp_sendloguw(c20p1305nvcounter);
		lcdtp_sendlogs(":nvconuter\n");
	}
	for (;;) {
		dly_tsk(200);
		while (wroom4cmd("AT+RST\r\n", "OK", 2000) < 0)
			;
		dly_tsk(1000);
		if (wroom4cmd("ATE0\r\n", "OK", 1000) < 0)
			continue;
		dly_tsk(50);
		if (wroom4cmd("AT+CWMODE_CUR=1\r\n", "OK", 1000) < 0)
			continue;
		dly_tsk(50);
#if 0
		wroom4cmd("AT+CWSTARTSMART\r\n", "!a#s$d%f&g", 15000);
		wroom4cmd("AT+CWSTOPSMART\r\n", "OK", 1000);
		dly_tsk(100);
#else
		if (wroom4cmd("AT+CWDHCP_CUR=1,1\r\n", "OK", 1000) < 0)
			continue;
		dly_tsk(50);
		if (wroom4cmd("AT+CWJAP_CUR=\"SSID\",\"PASS\"\r\n", "OK", 10000) < 0)
			continue;
		dly_tsk(50);
		break;
	}
	for (count0=0; count0<20; count0++) {
		static	const	UB	req[] = "GET /wifi0/?id=0&key0c20=";
		static	const	UB	req2[] = " HTTP/1.0\r\nHost:wifi.something.com\r\nConnection:close\r\n\r\n";
		static	const	UB	*bin2hex = "0123456789abcdef";
		static	UB	buf[] = "AT+CIPSEND=0000\r\n";
		static	UB	str[4];
		UB	*p;
		W	l, l2;
		
		c20p1305vcounter += 2;
		c20p1305nonce[4] = c20p1305nvcounter >> 24;
		c20p1305nonce[5] = c20p1305nvcounter >> 16;
		c20p1305nonce[6] = c20p1305nvcounter >> 8;
		c20p1305nonce[7] = c20p1305nvcounter;
		c20p1305nonce[8] = c20p1305vcounter >> 24;
		c20p1305nonce[9] = c20p1305vcounter >> 16;
		c20p1305nonce[10] = c20p1305vcounter >> 8;
		c20p1305nonce[11] = c20p1305vcounter;
		
		str[0] = bin2hex[0];
		str[1] = bin2hex[0];
		str[2] = bin2hex[((count0 / 10) % 10) & 0xf];
		str[3] = bin2hex[(count0 % 10) & 0xf];
		
		wroom4cmd("AT+CIPSTART=\"TCP\",\"wifi.something.com\",80\r\n", "OK", -1);
		dly_tsk(50);
		
		l = 0;
		while ((req[l]))
			l++;
		l2 = 0;
		while ((req2[l2]))
			l2++;
		l = l + l2 + 24 + 8 + 32;
		p = buf;
		while (*(p++) != '=')
			;
		if (l >= 1000)
			*(p++) = bin2hex[((l / 1000) % 10) & 0xf];
		if (l >= 100)
			*(p++) = bin2hex[((l / 100) % 10) & 0xf];
		if (l >= 10)
			*(p++) = bin2hex[((l / 10) % 10) & 0xf];
		*(p++) = bin2hex[(l % 10) & 0xf];
		*(p++) = 0xd;
		*(p++) = 0xa;
		*(p++) = 0;
		wroom4cmd(buf, "OK", -1);
		
		wroom4cmd(req, NULL, -1);
		c20p1305_send(NULL, -1, c20p1305key, c20p1305nonce, wroom4ub);
		c20p1305_send(str, 4, c20p1305key, c20p1305nonce, wroom4ub);
		c20p1305_send(NULL, 0, c20p1305key, c20p1305nonce, wroom4ub);
		wroom4cmd(req2, NULL, -1);
		if ((c20p1305nonce[11] & 1) == 0) {
			static	UB	recvbuf[256];
			W	pos;
			W	c, upper;
			
			c20p1305nonce[11] |= 1;
			
			wroom4cmd(req2, "key0c20=", -1);
			pos = 0;
			upper = -1;
			while (pos < sizeof(recvbuf)) {
				c = c4wroom(-1);
				if ((c >= '0')&&(c <= '9'))
					c = c - '0';
				else if ((c >= 'A')&&(c <= 'F'))
					c = c - 'A' + 0xa;
				else if ((c >= 'a')&&(c <= 'f'))
					c = c - 'a' + 0xa;
				else
					break;
				if (upper < 0) {
					upper = c << 4;
					continue;
				}
				c |= upper;
				upper = -1;
				recvbuf[pos++] = c;
			}
			wroom4cmd("", "\nCLOSED", -1);
			if (pos >= 12 + 16) {
				static	UB	mac[16];
				W	i;
				
				for (i=0; i<12; i++)
					if (recvbuf[i] != c20p1305nonce[i]) {
						lcdtp_sendlogs("nonce not match.\n");
						break;
					}
				c20p1305_mac(mac, NULL, 0, recvbuf + 12, pos - 12 - 16, c20p1305key, c20p1305nonce);
				for (i=0; i<sizeof(mac); i++)
					if (recvbuf[pos - sizeof(mac) + i] != mac[i]) {
						lcdtp_sendlogs("mac not match.\n");
						break;
					}
				c20p1305_xor(recvbuf + 12, pos - 12 - 16, c20p1305key, c20p1305nonce);
				for (i=12; i<pos-16; i++) {
					static	UB	s[2] = {'0', 0};
					
					s[0] = recvbuf[i];
					lcdtp_sendlogs(s);
				}
				lcdtp_sendlogs(":recv\n");
			}
		} else
			wroom4cmd("", "\nCLOSED", -1);
		dly_tsk(2000);
	}
#endif
	lcdtp_sendlogs("\ntest done.\n");
	for (;;) {
		UB	c;
		
		if ((U1STAbits.OERR))
			U1STA = 0x1400;
		if (U1STAbits.URXDA == 0)
			continue;
		c = U1RXREG;
		lcdtp_sendlogc(c);
	}
	
	tplib_setupflip("smallest-touchpanel-ui");
	for (;;) {
		tplib_proc(parts, gettp());
	}
	
	return 0;
}


