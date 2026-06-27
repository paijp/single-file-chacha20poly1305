
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

#ifndef	WIFI_HOST
#define	WIFI_HOST	wifi.something.com
#endif
#define	_STR(x)		#x
#define	STR(x)		_STR(x)

#define	SSID_MAX	32
#define	PASS_MAX	64
static	UW	stored_ssid_w[(SSID_MAX + 4) / 4] = {0};
static	UW	stored_pass_w[(PASS_MAX + 4) / 4] = {0};
#define	stored_ssid	((UB*)stored_ssid_w)
#define	stored_pass	((UB*)stored_pass_w)


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
	
	static	UB	s[3] = {'0', '0', 0};

	s[0] = bin2hex[(c >> 4) & 0xf];
	s[1] = bin2hex[c & 0xf];
	wroom4cmd(s, NULL, -1);
	return 1;
}


#define	FLASHPAGEWORDS	(1024 / sizeof(UW))

/*
	Two pages so a power loss mid-update still leaves one valid copy:
	always write the unselected page first, then the other. Each page
	stores the counter in its first half with a bit-inverted copy in the
	second half (see checkflashpage / writeflashpage).
*/
static	const	UW	flashpage0[FLASHPAGEWORDS] __attribute__((aligned(1024))) = {0};
static	const	UW	flashpage1[FLASHPAGEWORDS] __attribute__((aligned(1024))) = {0};
static	const	UW	cfgpage0[FLASHPAGEWORDS] __attribute__((aligned(1024))) = {0};
static	const	UW	cfgpage1[FLASHPAGEWORDS] __attribute__((aligned(1024))) = {0};


static	void	nvmunlock(UW cmd)
{
	NVMCON = cmd;
	while ((NVMCONbits.LVDSTAT))
		;
	NVMKEY = 0xaa996655;
	NVMKEY = 0x556699aa;
	NVMCONSET = 0x8000;
	while ((NVMCON & 0x8000))
		;
	NVMCONCLR = 0x4000;
	dly_tsk(1);
}


static	void	writeflashpage_data(const volatile UW *mem, const UW *src)
{
	W	i;

	nvmunlock(0x4000);
	dly_tsk(200);
	nvmunlock(0x4000);

	NVMADDR = ((UW)mem) & 0x1fffffff;
	nvmunlock(0x4004);
	for (i=0; i<FLASHPAGEWORDS / 2; i++) {
		NVMADDR = ((UW)(mem + i)) & 0x1fffffff;
		NVMDATA = src[i];
		nvmunlock(0x4001);
	}
	for (i=0; i<FLASHPAGEWORDS / 2; i++) {
		NVMADDR = ((UW)(mem + FLASHPAGEWORDS / 2 + i)) & 0x1fffffff;
		NVMDATA = src[i] ^ 0xffffffff;
		nvmunlock(0x4001);
	}
}


static	void	writeflashpage(const volatile UW *mem, UW v)
{
	static	UW	buf[FLASHPAGEWORDS / 2];
	W	i;

	buf[0] = v;
	for (i=1; i<FLASHPAGEWORDS / 2; i++)
		buf[i] = 0;
	writeflashpage_data(mem, buf);
}


static	W	checkflashpage(const volatile UW *mem)
{
	W	i;

	for (i=0; i<FLASHPAGEWORDS / 2; i++)
		if ((mem[i] ^ mem[i + FLASHPAGEWORDS / 2]) != 0xffffffff)
			return -1;
	return mem[0];
}


static	void	load_cfg_from_flash(void)
{
	const	volatile	UW	*mem = NULL;
	W	i;

	if (checkflashpage(cfgpage0) >= 0)
		mem = cfgpage0;
	else if (checkflashpage(cfgpage1) >= 0)
		mem = cfgpage1;
	if (mem == NULL) {
		stored_ssid[0] = 0;
		stored_pass[0] = 0;
		return;
	}
	for (i=0; i<SSID_MAX / 4; i++)
		stored_ssid_w[i] = mem[i];
	stored_ssid[SSID_MAX] = 0;
	for (i=0; i<PASS_MAX / 4; i++)
		stored_pass_w[i] = mem[SSID_MAX / 4 + i];
	stored_pass[PASS_MAX] = 0;
}


static	void	save_cfg_to_flash(void)
{
	static	UW	buf[FLASHPAGEWORDS / 2];
	UB	*bbuf = (UB*)buf;
	W	i;

	for (i=0; i<sizeof(buf); i++)
		bbuf[i] = 0;
	for (i=0; i<SSID_MAX && stored_ssid[i]; i++)
		bbuf[i] = stored_ssid[i];
	for (i=0; i<PASS_MAX && stored_pass[i]; i++)
		bbuf[SSID_MAX + i] = stored_pass[i];
	writeflashpage_data(cfgpage0, buf);
	writeflashpage_data(cfgpage1, buf);
}


/* Parse "WIFI:T:<auth>;S:<ssid>;P:<password>;[H:...];" into stored_ssid/pass.
   Backslash escapes the next char so passwords with ';' or ':' work. */
static	void	parse_wifi_barcode(const UB *s)
{
	const	UB	*p = s;
	UB	tag;
	UB	*out;
	W	max, i;

	if (p[0] != 'W' || p[1] != 'I' || p[2] != 'F' || p[3] != 'I' || p[4] != ':')
		return;
	p += 5;
	stored_ssid[0] = 0;
	stored_pass[0] = 0;
	while (*p && *p != ';') {
		tag = p[0];
		if (p[1] != ':') {
			while (*p && *p != ';') p++;
			if (*p == ';') p++;
			continue;
		}
		p += 2;
		if (tag == 'S' || tag == 'P') {
			out = (tag == 'S') ? stored_ssid : stored_pass;
			max = (tag == 'S') ? SSID_MAX : PASS_MAX;
			i = 0;
			while (*p && *p != ';') {
				if (*p == '\\' && p[1])
					p++;
				if (i < max)
					out[i++] = *p;
				p++;
			}
			out[i] = 0;
		} else {
			while (*p && *p != ';') p++;
		}
		if (*p == ';') p++;
	}
}


/* Simulated USB-HID barcode reader: pretend a Wi-Fi QR was scanned. */
static	void	simulate_barcode(void)
{
	static	const	UB	demo[] = "WIFI:T:WPA;S:BZ02_7099;P:tmpyywwqq;;";

	lcdtp_sendlogs("simulated barcode:\n");
	lcdtp_sendlogs(demo);
	lcdtp_sendlogs("\n");
	parse_wifi_barcode(demo);
	lcdtp_sendlogs("ssid=");
	lcdtp_sendlogs(stored_ssid);
	lcdtp_sendlogs("\npass=");
	lcdtp_sendlogs(stored_pass);
	lcdtp_sendlogs("\n");
	save_cfg_to_flash();
	lcdtp_sendlogs("saved.\n");
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
	
	{
		/* very-early U2 marker: '@' before anything else. Clocks are stable
		   by now (FRC+PLL locks before crt0 calls main). */
		volatile	UW	dly;

		RPB10R = 2;
		U2BRG = 86;
		U2MODE = 0x8008;
		U2STA = 0x1400;
		for (dly=0; dly<10000; dly++) ;
		while ((U2STAbits.UTXBF))
			;
		U2TXREG = '@';
		for (dly=0; dly<50000; dly++) ;
	}
	init_lcdtp();
	
	RPB15R = 1;		/* UTX1 */
	U1RXR = 3;		/* RPB13 */
	TRISBbits.TRISB13 = 1;
	CNPUBbits.CNPUB13 = 0;
	U1MODE = 0;
	U1BRG = (10000000 / 115200) - 1;
	U1MODE = 0x8008;		/* enable N81 4(U2BRG + 1) */
	U1STA = 0x1400;

	U2RXR = 3;		/* RPB11 — listen on same line /dev/ttyACM0 uses */
	TRISBbits.TRISB11 = 1;

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

		if ((i = checkflashpage(flashpage0)) >= 0)
			c20p1305nvcounter = i;
		lcdtp_sendloguw(i);
		lcdtp_sendlogs(":page0\n");
		if ((i = checkflashpage(flashpage1)) >= 0)
			c20p1305nvcounter = i;
		lcdtp_sendloguw(i);
		lcdtp_sendlogs(":page1\n");

		writeflashpage(flashpage0, c20p1305nvcounter + 1);
		writeflashpage(flashpage1, c20p1305nvcounter + 1);
		lcdtp_sendloguw(c20p1305nvcounter);
		lcdtp_sendlogs(":nvconuter\n");
	}
	lcdtp_sendlogs("M1\n");
	load_cfg_from_flash();
	lcdtp_sendlogs("M2\n");
	(void)simulate_barcode;  /* force link without calling */
	lcdtp_sendlogs("ssid=[");
	lcdtp_sendlogs((char*)stored_ssid);
	lcdtp_sendlogs("]\n");
	lcdtp_sendlogs("M3\n");
	/* Wait for 'X' then run the simulated barcode reader. */
	while (stored_ssid[0] == 0) {
		if ((U2STAbits.URXDA)) {
			UB	c = U2RXREG;
			if (c == 'X')
				simulate_barcode();
		}
		dly_tsk(100);
	}
	lcdtp_sendlogs("M4\n");
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
		if (wroom4cmd("AT+CWDHCP_CUR=1,1\r\n", "OK", 1000) < 0)
			continue;
		dly_tsk(50);
		{
			static	UB	cmdbuf[16 + SSID_MAX + 4 + PASS_MAX + 4];
			const	UB	*s;
			W	p = 0;

			for (s = (const UB*)"AT+CWJAP_CUR=\""; *s; s++) cmdbuf[p++] = *s;
			for (s = stored_ssid; *s; s++)                 cmdbuf[p++] = *s;
			for (s = (const UB*)"\",\""; *s; s++)          cmdbuf[p++] = *s;
			for (s = stored_pass; *s; s++)                 cmdbuf[p++] = *s;
			for (s = (const UB*)"\"\r\n"; *s; s++)         cmdbuf[p++] = *s;
			cmdbuf[p] = 0;
			if (wroom4cmd(cmdbuf, "OK", 10000) < 0)
				continue;
		}
		dly_tsk(50);
		break;
	}
	for (count0=0; count0<20; count0++) {
		static	const	UB	req[] = "GET /wifi0/?id=0&key0c20=";
		static	const	UB	req2[] = " HTTP/1.0\r\nHost:" STR(WIFI_HOST) "\r\nConnection:close\r\n\r\n";
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
		
		wroom4cmd("AT+CIPSTART=\"TCP\",\"" STR(WIFI_HOST) "\",80\r\n", "OK", -1);
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


