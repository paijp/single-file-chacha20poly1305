
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

#include	"c20p1305.h"
#include	"i2c.h"

#pragma config  PMDL1WAY=OFF, IOL1WAY=OFF, FUSBIDIO=OFF, FVBUSONIO=OFF
#pragma config  FPLLIDIV=DIV_1, FPLLMUL=MUL_20, UPLLIDIV=DIV_1, UPLLEN=OFF
#pragma	config	FPLLODIV=DIV_2, FNOSC=FRCPLL, FSOSCEN=OFF, IESO=OFF
#pragma	config	POSCMOD=XT, OSCIOFNC=OFF, FPBDIV=DIV_1, FCKSM=CSECMD
#pragma	config	WDTPS=PS16384, WINDIS=OFF, FWDTEN=OFF, FWDTWINSZ=WINSZ_50
#pragma	config	DEBUG=OFF, JTAGEN=OFF, ICESEL=ICS_PGx2, PWP=OFF
/* CP=ON: code protection — the flash pages hold Wi-Fi credentials and the
   ChaCha20 key, so block external readout. */
#pragma	config	BWP=OFF, CP=ON

/*
	UART-barcode-reader variant: for BARCODE_WINDOW_MS (10 s) after boot the
	WROOM's TX pin is switched to GPIO-input, releasing the WROOM->PIC32 line
	to a 9600 bps serial barcode reader wired in through a weak resistor.
	Scans captured in that window are parsed and saved to flash:
	  WIFI:T:WPA;S:<ssid>;P:<password>;;
	  C20P:K:<64-hex-key>;U:<full URL up to "key0c20=">;;
	After the window closes, the line reverts to 115200 bps WROOM AT traffic
	and the stored credentials drive the normal connect/request flow.

	(A USB-host variant will replace the UART capture; this one exists to
	verify the barcode/flash path with full debug output first.)
*/


/* Runtime Wi-Fi credentials, loaded from flash at boot, set via 'X' barcode. */
#define	SSID_MAX	32
#define	PASS_MAX	64
static	UB	stored_ssid[SSID_MAX + 1] = {0};
static	UB	stored_pass[PASS_MAX + 1] = {0};

/* Runtime ChaCha20 key + endpoint URL, set via 'Y' barcode. */
#define	URL_MAX		224
static	UB	stored_key[32] = {0};
static	UB	stored_url[URL_MAX + 1] = {0};
static	UB	stored_host[64] = {0};
static	const	UB	*stored_path = (const UB*)"";

/* Built once after Wi-Fi associates, then sent each request iteration. */
static	UB	req[8 + URL_MAX] = {0};
static	UB	req2[64 + 64] = {0};
static	UB	cipstart[24 + 64] = {0};


static	UB	c20p1305nonce[12] = {0};
static	UW	c20p1305nvcounter = 0;
static	UW	c20p1305vcounter = 0;


void	(*lcdtp_polltask)() = NULL;


static	void	wait100us(void)
{
	long	l;

	if ((lcdtp_polltask))
		lcdtp_polltask();

	for (l=1500; l>0; l--)
		asm("nop");
}


void	dly_tsk(W ms)
{
	ms *= 10;
	while (ms-- > 0)
		wait100us();
}


void	lcdtp_sendlogc(W c)
{
	static	W	first = 1;

	if ((first)) {
		first = 0;

		RPB10R = 2;		/* UTX2 */
		U2MODE = 0;
		U2BRG = 86;		/* 115.4kbps */
		U2MODE = 0x8008;	/* enable N81 4(U2BRG + 1) */
		U2STA = 0x1400;
	}
	for (;;) {
		if (U2STAbits.UTXBF == 0) {
			U2TXREG = c;
			return;
		}
		if ((lcdtp_polltask))
			lcdtp_polltask();
	}
}


void	lcdtp_sendlogs(const char *s)
{
	W	c;

	while ((c = *(s++)))
		lcdtp_sendlogc(c);
}


void	lcdtp_sendlogdec(W v)
{
	if ((v < 0)) {
		v = -v;
		lcdtp_sendlogc('-');
	}
	if (v >= 10)
		lcdtp_sendlogdec(v / 10);
	lcdtp_sendlogc('0' + (v % 10));
}


void	lcdtp_sendlogun(UW v)
{
	static	const	char *bin2hex = "0123456789abcdef";

	lcdtp_sendlogc(bin2hex[v & 0xf]);
}


void	lcdtp_sendlogub(UW v)
{
	lcdtp_sendlogun(v >> 4);
	lcdtp_sendlogun(v);
}


void	lcdtp_sendloguh(UW v)
{
	lcdtp_sendlogun(v >> 12);
	lcdtp_sendlogun(v >> 8);
	lcdtp_sendlogun(v >> 4);
	lcdtp_sendlogun(v);
}


void	lcdtp_sendloguw(UW v)
{
	lcdtp_sendlogun(v >> 28);
	lcdtp_sendlogun(v >> 24);
	lcdtp_sendlogun(v >> 20);
	lcdtp_sendlogun(v >> 16);
	lcdtp_sendlogun(v >> 12);
	lcdtp_sendlogun(v >> 8);
	lcdtp_sendlogun(v >> 4);
	lcdtp_sendlogun(v);
}


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

/* One page each for Wi-Fi and ChaCha20+URL: a barcode can be rescanned if a
   write is interrupted, so no need for a redundant backup page. */
static	const	UW	cfgpage_wifi[FLASHPAGEWORDS] __attribute__((aligned(1024))) = {0};
static	const	UW	cfgpage_app[FLASHPAGEWORDS]  __attribute__((aligned(1024))) = {0};


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


/* Returns 0 if the page passes the bit-inversion redundancy check, -1 if
   not. Callers that want the first word read it from mem[0] themselves —
   returning it here would conflate "first word looks negative" with "page
   invalid" once a key with the high bit set lives there. */
static	W	checkflashpage(const volatile UW *mem)
{
	W	i;

	for (i=0; i<FLASHPAGEWORDS / 2; i++)
		if ((mem[i] ^ mem[i + FLASHPAGEWORDS / 2]) != 0xffffffff)
			return -1;
	return 0;
}


static	void	load_wifi_from_flash(void)
{
	const	volatile	UW	*mem = cfgpage_wifi;
	W	i;

	if (checkflashpage(mem) < 0) {
		stored_ssid[0] = 0;
		stored_pass[0] = 0;
		return;
	}
	for (i=0; i<SSID_MAX / 4; i++)
		((UW*)stored_ssid)[i] = mem[i];
	stored_ssid[SSID_MAX] = 0;
	for (i=0; i<PASS_MAX / 4; i++)
		((UW*)stored_pass)[i] = mem[SSID_MAX / 4 + i];
	stored_pass[PASS_MAX] = 0;
}


static	void	save_wifi_to_flash(void)
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
	writeflashpage_data(cfgpage_wifi, buf);
}


/* Split stored_url (e.g. "http://host/path?...key0c20=") into stored_host
   and stored_path. Tolerates missing scheme and missing path. */
static	void	parse_stored_url(void)
{
	const	UB	*p = stored_url;
	W	i;

	stored_host[0] = 0;
	stored_path = (const UB*)"";
	if (p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p') {
		p += 4;
		if (*p == 's') p++;
		if (p[0] == ':' && p[1] == '/' && p[2] == '/') p += 3;
	}
	i = 0;
	while (*p && *p != '/' && *p != ':' && i < (W)sizeof(stored_host) - 1)
		stored_host[i++] = *p++;
	stored_host[i] = 0;
	while (*p && *p != '/')
		p++;	/* skip optional :port */
	stored_path = p;
}


static	void	load_app_from_flash(void)
{
	const	volatile	UW	*mem = cfgpage_app;
	W	i;

	if (checkflashpage(mem) < 0) {
		stored_key[0] = 0;
		stored_url[0] = 0;
		parse_stored_url();
		return;
	}
	for (i=0; i<8; i++)
		((UW*)stored_key)[i] = mem[i];
	for (i=0; i<URL_MAX / 4; i++)
		((UW*)stored_url)[i] = mem[8 + i];
	stored_url[URL_MAX] = 0;
	parse_stored_url();
}


static	void	save_app_to_flash(void)
{
	static	UW	buf[FLASHPAGEWORDS / 2];
	UB	*bbuf = (UB*)buf;
	W	i;

	for (i=0; i<sizeof(buf); i++)
		bbuf[i] = 0;
	for (i=0; i<32; i++)
		bbuf[i] = stored_key[i];
	for (i=0; i<URL_MAX && stored_url[i]; i++)
		bbuf[32 + i] = stored_url[i];
	writeflashpage_data(cfgpage_app, buf);
}


/* Hex digit -> nibble (0..15), or -1 on garbage. */
static	W	hex2nib(W c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 0xa;
	if (c >= 'A' && c <= 'F') return c - 'A' + 0xa;
	return -1;
}


/* Generic tag-prefixed field copier: advances *pp past the value (and its
   trailing ';'). out may be NULL to skip. '\\' escapes the next char. */
static	void	copy_field(const UB **pp, UB *out, W max)
{
	const	UB	*p = *pp;
	W	i = 0;

	while (*p && *p != ';') {
		if (*p == '\\' && p[1])
			p++;
		if (out && i < max)
			out[i++] = *p;
		p++;
	}
	if (out)
		out[i] = 0;
	if (*p == ';')
		p++;
	*pp = p;
}


/* Parse "WIFI:T:<auth>;S:<ssid>;P:<password>;[H:<true|false>];" into
   stored_ssid / stored_pass. Unknown tokens skipped. */
static	void	parse_wifi_barcode(const UB *s)
{
	const	UB	*p = s;
	UB	tag;

	if (p[0] != 'W' || p[1] != 'I' || p[2] != 'F' || p[3] != 'I' || p[4] != ':')
		return;
	p += 5;
	stored_ssid[0] = 0;
	stored_pass[0] = 0;
	while (*p && *p != ';') {
		tag = p[0];
		if (p[1] != ':') {
			copy_field(&p, NULL, 0);
			continue;
		}
		p += 2;
		switch (tag) {
		case 'S':	copy_field(&p, stored_ssid, SSID_MAX);	break;
		case 'P':	copy_field(&p, stored_pass, PASS_MAX);	break;
		default:	copy_field(&p, NULL, 0);		break;
		}
	}
}


/* Parse "C20P:K:<64-hex chars>;U:<url>;;" into stored_key / stored_url.
   K: must be exactly 64 hex chars (32 bytes); malformed → key cleared. */
static	void	parse_c20p_barcode(const UB *s)
{
	const	UB	*p = s;
	UB	tag;
	W	i, hi, lo;

	if (p[0] != 'C' || p[1] != '2' || p[2] != '0' || p[3] != 'P' || p[4] != ':')
		return;
	p += 5;
	for (i=0; i<32; i++) stored_key[i] = 0;
	stored_url[0] = 0;
	while (*p && *p != ';') {
		tag = p[0];
		if (p[1] != ':') {
			copy_field(&p, NULL, 0);
			continue;
		}
		p += 2;
		switch (tag) {
		case 'K':
			for (i=0; i<32; i++) {
				if ((hi = hex2nib(*p)) < 0) break;
				p++;
				if ((lo = hex2nib(*p)) < 0) break;
				p++;
				stored_key[i] = (hi << 4) | lo;
			}
			copy_field(&p, NULL, 0);	/* skip rest until ';' */
			break;
		case 'U':
			copy_field(&p, stored_url, URL_MAX);
			break;
		default:
			copy_field(&p, NULL, 0);
			break;
		}
	}
	parse_stored_url();
}


/*
	Serial barcode reader window.

	The barcode reader (9600 bps) is wired through a weak resistor onto the
	WROOM->PIC32 line. Normally the WROOM's TX drives that line; switching
	the WROOM's pin to GPIO-input releases it so the reader's levels win.
	For BARCODE_WINDOW_MS after boot we listen at 9600 bps, then give the
	line back to the WROOM and return to 115200 bps AT traffic.

	Scans found in the window are dispatched by prefix:
	  WIFI:...  -> parse_wifi_barcode + save_wifi_to_flash
	  C20P:...  -> parse_c20p_barcode + save_app_to_flash
	A reader typically terminates each scan with CR and/or LF; we split on
	those and ignore empty/unknown lines.
*/
#define	BARCODE_WINDOW_MS	10000

static	W	memsame(const UB *a, const UB *b, W len)
{
	while (len-- > 0)
		if (*(a++) != *(b++))
			return 0;
	return 1;
}


/* A reader may deliver the same scan several times in one window; comparing
   the parsed values against what's already stored avoids rewriting (and
   wearing) the flash page for every repeat. */
static	void	barcode_line(const UB *line)
{
	static	UB	prev_ssid[SSID_MAX + 1], prev_pass[PASS_MAX + 1];
	static	UB	prev_key[32], prev_url[URL_MAX + 1];
	W	i;

	if (line[0] == 0)
		return;
	lcdtp_sendlogs("barcode: ");
	lcdtp_sendlogs(line);
	lcdtp_sendlogs("\n");
	if (line[0] == 'W' && line[1] == 'I' && line[2] == 'F' && line[3] == 'I'
	    && line[4] == ':') {
		for (i=0; i<(W)sizeof(prev_ssid); i++) prev_ssid[i] = stored_ssid[i];
		for (i=0; i<(W)sizeof(prev_pass); i++) prev_pass[i] = stored_pass[i];
		parse_wifi_barcode(line);
		if (memsame(prev_ssid, stored_ssid, sizeof(prev_ssid))
		    && memsame(prev_pass, stored_pass, sizeof(prev_pass))) {
			lcdtp_sendlogs("wifi unchanged.\n");
			return;
		}
		lcdtp_sendlogs("ssid=");
		lcdtp_sendlogs(stored_ssid);
		lcdtp_sendlogs("\n");
		save_wifi_to_flash();
		lcdtp_sendlogs("wifi saved.\n");
	} else if (line[0] == 'C' && line[1] == '2' && line[2] == '0'
	    && line[3] == 'P' && line[4] == ':') {
		for (i=0; i<(W)sizeof(prev_key); i++) prev_key[i] = stored_key[i];
		for (i=0; i<(W)sizeof(prev_url); i++) prev_url[i] = stored_url[i];
		parse_c20p_barcode(line);
		if (memsame(prev_key, stored_key, sizeof(prev_key))
		    && memsame(prev_url, stored_url, sizeof(prev_url))) {
			lcdtp_sendlogs("app unchanged.\n");
			return;
		}
		lcdtp_sendlogs("url=");
		lcdtp_sendlogs(stored_url);
		lcdtp_sendlogs("\n");
		save_app_to_flash();
		lcdtp_sendlogs("app saved.\n");
	} else
		lcdtp_sendlogs("(unknown prefix, ignored)\n");
}


static	void	barcode_window(void)
{
	static	UB	buf[1024];
	W	size;
	W	tmout;
	W	v;
	W	head;

	/* Release the WROOM->PIC32 line: WROOM pin 1 to GPIO input. */
	wroom4cmd("AT+SYSIOSETCFG=1,3,0\r\n", "OK", 200);	/* gpio */
	wroom4cmd("AT+SYSGPIODIR=1,0\r\n", "OK", 200);		/* input */
	dly_tsk(100);

	/* Barcode reader talks at 9600 bps. */
	U1MODE = 0;
	U1BRG = (10000000 / 9600) - 1;
	U1MODE = 0x8008;		/* enable N81 4(U1BRG + 1) */
	U1STA = 0x1400;

	lcdtp_sendlogs("scan window open\n");
	size = 0;
	tmout = BARCODE_WINDOW_MS;
	while (tmout > 0) {
		if ((IFS0bits.T2IF)) {
			IFS0bits.T2IF = 0;
			tmout--;
		}
		if ((U1STAbits.OERR))
			U1STA = 0x1400;
		if (U1STAbits.URXDA == 0)
			continue;
		v = U1RXREG;
		if (size < (W)sizeof(buf) - 2)
			buf[size++] = v;
	}
	buf[size] = 0;

	/* Back to the WROOM: 115200 bps, pin 1 back to TX duty. */
	U1MODE = 0;
	U1BRG = (10000000 / 115200) - 1;
	U1MODE = 0x8008;		/* enable N81 4(U1BRG + 1) */
	U1STA = 0x1400;
	dly_tsk(100);
	wroom4cmd("AT+SYSGPIODIR=1,1\r\n", "OK", 200);		/* output */
	wroom4cmd("AT+SYSIOSETCFG=1,0,0\r\n", "OK", 200);	/* TX */
	lcdtp_sendlogs("scan window closed\n");

	/* Split the captured bytes on CR/LF and dispatch each scan. */
	head = 0;
	for (v=0; v<size; v++) {
		if (buf[v] != 0xd && buf[v] != 0xa)
			continue;
		buf[v] = 0;
		barcode_line(buf + head);
		head = v + 1;
	}
	barcode_line(buf + head);	/* unterminated tail, if any */
}


int	main(int ac, char **av)
{
	W	count0;

	CNPUA = 0xffff;
	CNPUB = 0xffff;

	CNPDB = 0;
	CNPDB = 0;

	TRISA = 0x0000;		/* -------- ---O--OO */
	TRISB = 0x0000;		/* OOO---OO O-OOOOOO */

	ANSELA = 0;
	ANSELB = 0;

	PORTA = 0xffff;
	PORTB = 0xffff;

	SYSKEY = 0;
	SYSKEY = 0xaa996655;
	SYSKEY = 0x556699aa;
	SYSKEY = 0;

	RPB15R = 1;		/* UTX1 */
	U1RXR = 3;		/* RPB13 */
	TRISBbits.TRISB13 = 1;
	CNPUBbits.CNPUB13 = 0;
	U1MODE = 0;
	U1BRG = (10000000 / 115200) - 1;
	U1MODE = 0x8008;		/* enable N81 4(U2BRG + 1) */
	U1STA = 0x1400;

	/* U2RX on RPB11: the same line /dev/ttyACM0 talks to (the bootloader's ':'
	   hex-write mode passes other bytes through to U2RX). U2 TX/baud are set
	   up lazily on first lcdtp_sendlogc call. */
	U2RXR = 3;		/* RPB11 */
	TRISBbits.TRISB11 = 1;

	T2CON = 0x0070;		/* 1/256 */
	TMR2 = 0;
	PR2 = 156;		/* 40M / 256 / 1000Hz */
	T2CON = 0x8070;

	i2cstop();

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
		if (checkflashpage(flashpage0) >= 0)
			c20p1305nvcounter = flashpage0[0];
		lcdtp_sendloguw(c20p1305nvcounter);
		lcdtp_sendlogs(":page0\n");
		if (checkflashpage(flashpage1) >= 0)
			c20p1305nvcounter = flashpage1[0];
		lcdtp_sendloguw(c20p1305nvcounter);
		lcdtp_sendlogs(":page1\n");

		writeflashpage(flashpage0, c20p1305nvcounter + 1);
		writeflashpage(flashpage1, c20p1305nvcounter + 1);
		lcdtp_sendloguw(c20p1305nvcounter);
		lcdtp_sendlogs(":nvconuter\n");
	}
	load_wifi_from_flash();
	load_app_from_flash();
	lcdtp_sendlogs("ssid=");
	lcdtp_sendlogs((stored_ssid[0]) ? (char*)stored_ssid : "(unset)");
	lcdtp_sendlogs("\nurl=");
	lcdtp_sendlogs((stored_url[0])  ? (char*)stored_url  : "(unset)");
	lcdtp_sendlogs("\n");

	/* Bring the WROOM up far enough to control its GPIO, then open the
	   barcode scan window for BARCODE_WINDOW_MS. */
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
		break;
	}
	barcode_window();

	if (stored_ssid[0] == 0 || stored_url[0] == 0) {
		lcdtp_sendlogs("config incomplete (need WIFI: and C20P: scans); halted.\n");
		for (;;)
			;
	}

	for (;;) {
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
	{
		W	i;
		static	const	UB	pre[]  = " HTTP/1.0\r\nHost:";
		static	const	UB	suf[]  = "\r\nConnection:close\r\n\r\n";
		static	const	UB	cpre[] = "AT+CIPSTART=\"TCP\",\"";
		static	const	UB	csuf[] = "\",80\r\n";
		const	UB	*s;

		/* "GET <path>" — hex payload appended at send time, then req2. */
		i = 0;
		req[i++] = 'G'; req[i++] = 'E'; req[i++] = 'T'; req[i++] = ' ';
		for (s=stored_path; *s && i<(W)sizeof(req)-1; s++) req[i++] = *s;
		req[i] = 0;

		/* " HTTP/1.0\r\nHost:<host>\r\nConnection:close\r\n\r\n" */
		i = 0;
		for (s=pre; *s; s++) req2[i++] = *s;
		for (s=stored_host; *s; s++) req2[i++] = *s;
		for (s=suf; *s; s++) req2[i++] = *s;
		req2[i] = 0;

		/* AT+CIPSTART="TCP","<host>",80 */
		i = 0;
		for (s=cpre; *s; s++) cipstart[i++] = *s;
		for (s=stored_host; *s; s++) cipstart[i++] = *s;
		for (s=csuf; *s; s++) cipstart[i++] = *s;
		cipstart[i] = 0;
	}
	for (count0=0; count0<20; count0++) {
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

		wroom4cmd(cipstart, "OK", -1);
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
		c20p1305_send(NULL, -1, stored_key, c20p1305nonce, wroom4ub);
		c20p1305_send(str, 4, stored_key, c20p1305nonce, wroom4ub);
		c20p1305_send(NULL, 0, stored_key, c20p1305nonce, wroom4ub);
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
				c20p1305_mac(mac, NULL, 0, recvbuf + 12, pos - 12 - 16, stored_key, c20p1305nonce);
				for (i=0; i<sizeof(mac); i++)
					if (recvbuf[pos - sizeof(mac) + i] != mac[i]) {
						lcdtp_sendlogs("mac not match.\n");
						break;
					}
				c20p1305_xor(recvbuf + 12, pos - 12 - 16, stored_key, c20p1305nonce);
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

	for (;;)
		;

	return 0;
}
