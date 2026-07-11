
/*
	Single file chacha20poly1305 https://github.com/paijp/single-file-chacha20poly1305

	License: MIT or PUBLIC DOMAIN.

	USB-HID barcode reader variant.

	main() is the USB host loop from pic32mx-usb-minimal (dev/host/
	usbhost0015.c, Apache-2.0): it enumerates a printer or a HID boot
	keyboard and services it. A USB barcode reader in keyboard mode types
	its scans; those characters are collected into a line buffer and
	dispatched on Enter to the same WIFI: / C20P: parsers as the UART
	variant, saving to flash.

	Application flow rides on the usb_polltask hook: app_init() (called
	before the USB loop) brings up the WROOM and opens a 10 s scan window;
	app_polltask() — invoked from every USB busy-wait — watches the window
	expire and then runs the Wi-Fi connect + encrypted test exchange
	inline, not returning to USB processing until done. That stall is
	acceptable here: barcode scanning is over once the window closes.

	Debug log rides UTX2 on RPB0/PGED1 (RB10/RB11 are the USB D+/D- pins, so the
	usual PGD/PGC-pin UART is unavailable — the "restricted debug" of this
	variant).

	USB host portion:
	Copyright (c) 2026 paijp — Apache License 2.0
	  https://github.com/paijp/pic32mx-usb-minimal
	Developed in collaboration with Anthropic's Claude.
*/

#include <xc.h>
#include <sys/attribs.h>
#include <stdint.h>

#include "c20p1305.h"

/* ============================================================
 * Configuration bits (usbhost0015.c set; USB needs the 48 MHz UPLL)
 * ============================================================ */
#pragma config FPLLIDIV = DIV_1
#pragma config FPLLMUL  = MUL_20
#pragma config FPLLODIV = DIV_2
#pragma config FNOSC    = PRIPLL
#pragma config POSCMOD  = XT
#pragma config FSOSCEN  = OFF
#pragma config UPLLIDIV = DIV_1
#pragma config UPLLEN   = ON
#pragma config FPBDIV   = DIV_1
#pragma config FWDTEN   = OFF
#pragma config JTAGEN   = OFF
/* CP=ON: the flash pages hold Wi-Fi credentials and the ChaCha20 key. */
#pragma config CP       = ON


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

		RPB0R = 2;		/* UTX2 on RPB0/PGED1 — the writer's debug line.
					   RB10/RB11 are the USB D+/D- pins here. */
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


/* ============================================================
 * Scan window + application hook state
 * ============================================================ */
static	W	window_ms_left = BARCODE_WINDOW_MS;
static	W	app_done = 0;
static	W	in_polltask = 0;
static	W	g_wifi_ok = 0;


/*
	Byte-stream layer over the WROOM's active-mode TCP output: strips the
	"+IPD,<len>:" framing so a response spanning several TCP segments reads
	as one continuous stream. Returns the next payload byte, or -1 once the
	connection reports CLOSED before another data frame. Call ipd_reset()
	before each response.
*/
static	W	ipd_remain = 0;

static	void	ipd_reset(void)
{
	ipd_remain = 0;
}

static	W	ipd_getc(void)
{
	static	const	UB	hdr[] = "+IPD,";
	static	const	UB	closed[] = "CLOSED";
	const	UB	*p = hdr;
	const	UB	*q = closed;
	W	c, len;

	if (ipd_remain <= 0) {
		for (;;) {
			c = c4wroom(-1);
			lcdtp_sendlogc(c);
			if (c == *p) {
				if (*(++p) == 0)
					break;
			} else
				p = (c == hdr[0]) ? hdr + 1 : hdr;
			if (c == *q) {
				if (*(++q) == 0)
					return -1;
			} else
				q = (c == closed[0]) ? closed + 1 : closed;
		}
		len = 0;
		for (;;) {
			c = c4wroom(-1);
			lcdtp_sendlogc(c);
			if (c == ':')
				break;
			if (c >= '0' && c <= '9')
				len = len * 10 + (c - '0');
		}
		if (len <= 0)
			return -1;
		ipd_remain = len;
	}
	ipd_remain--;
	c = c4wroom(-1);
	lcdtp_sendlogc(c);
	return c;
}


/* Decoded reply capacity (nonce 12 + body + tag 16), advertised to the
   server as the "s" transport parameter so it never sends more than fits. */
#define	RECVBUF_SIZE	2048

/*
	One encrypted exchange with the server.

	payload/len ride in the query. wantreply=0 sets the nonce[11] LSB flag:
	the server still delivers the payload to its from_<id> FIFO and advances
	its replay state, but sends no body back and we don't wait for one.
	With wantreply=1 the decrypted reply body is copied into rbuf; returns
	its length (0 = empty/none, -1 = nonce/MAC mismatch).

	The plaintext starts with transport parameters — /[G-Zg-z][0-9A-Fa-f]+/
	tokens, key letters and hex digits being disjoint alphabets so no
	escaping is needed — followed by the application payload from the first
	/[G-Zg-z]=/ marker on (a bare '=' also ends the parameters, with the
	payload starting after it). The only parameter sent is "s<hex4>":
	RECVBUF_SIZE, e.g. "s0800p=18" for the 2 KB buffer.
*/
static	W	send_request(const UB *payload, W len, W wantreply, UB *rbuf, W rbufmax)
{
	static	const	UB	*bin2hex = "0123456789abcdef";
	static	UB	buf[] = "AT+CIPSEND=0000\r\n";
	UB	sparam[5];
	UB	*p;
	W	l, l2, sl;

	sparam[0] = 's';
	sparam[1] = bin2hex[(RECVBUF_SIZE >> 12) & 0xf];
	sparam[2] = bin2hex[(RECVBUF_SIZE >> 8) & 0xf];
	sparam[3] = bin2hex[(RECVBUF_SIZE >> 4) & 0xf];
	sparam[4] = bin2hex[RECVBUF_SIZE & 0xf];
	sl = 5;

	c20p1305vcounter += 2;
	c20p1305nonce[4] = c20p1305nvcounter >> 24;
	c20p1305nonce[5] = c20p1305nvcounter >> 16;
	c20p1305nonce[6] = c20p1305nvcounter >> 8;
	c20p1305nonce[7] = c20p1305nvcounter;
	c20p1305nonce[8] = c20p1305vcounter >> 24;
	c20p1305nonce[9] = c20p1305vcounter >> 16;
	c20p1305nonce[10] = c20p1305vcounter >> 8;
	c20p1305nonce[11] = c20p1305vcounter;
	if (!wantreply)
		c20p1305nonce[11] |= 1;

	wroom4cmd(cipstart, "OK", -1);
	dly_tsk(50);

	l = 0;
	while ((req[l]))
		l++;
	l2 = 0;
	while ((req2[l2]))
		l2++;
	l = l + l2 + 24 + (sl + len) * 2 + 32;
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
	c20p1305_send(sparam, sl, stored_key, c20p1305nonce, wroom4ub);
	c20p1305_send((UB*)payload, len, stored_key, c20p1305nonce, wroom4ub);
	c20p1305_send(NULL, 0, stored_key, c20p1305nonce, wroom4ub);
	wroom4cmd(req2, NULL, -1);
	if (!wantreply) {
		wroom4cmd("", "\nCLOSED", -1);
		return 0;
	}
	{
		static	UB	recvbuf[RECVBUF_SIZE];
		static	UB	mac[16];
		static	const	UB	marker[] = "key0c20=";
		const	UB	*mp;
		W	pos;
		W	c, upper;
		W	i;

		c20p1305nonce[11] |= 1;

		/* Hunt for "key0c20=" inside the de-framed +IPD stream, then read
		   hex until a non-hex byte or connection close. The response may
		   span several TCP segments; ipd_getc() hides the "+IPD,<n>:"
		   headers that would otherwise cut the hex short. */
		ipd_reset();
		mp = marker;
		for (;;) {
			if ((c = ipd_getc()) < 0)
				return 0;
			if (c == *mp) {
				if (*(++mp) == 0)
					break;
			} else
				mp = (c == marker[0]) ? marker + 1 : marker;
		}
		pos = 0;
		upper = -1;
		while (pos < (W)sizeof(recvbuf)) {
			if ((c = ipd_getc()) < 0)
				break;
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
		/* Drain the rest of the stream (trailing frame bytes and the
		   CLOSED notification) via ipd_getc, which returns -1 at CLOSED.
		   A separate blocking wait on the "CLOSED" marker would hang: by
		   now ipd_getc has already consumed it while framing. */
		while (c >= 0)
			c = ipd_getc();
		if (pos < 12 + 16)
			return 0;
		for (i=0; i<12; i++)
			if (recvbuf[i] != c20p1305nonce[i]) {
				lcdtp_sendlogs("nonce not match.\n");
				return -1;
			}
		c20p1305_mac(mac, NULL, 0, recvbuf + 12, pos - 12 - 16, stored_key, c20p1305nonce);
		for (i=0; i<(W)sizeof(mac); i++)
			if (recvbuf[pos - sizeof(mac) + i] != mac[i]) {
				lcdtp_sendlogs("mac not match.\n");
				return -1;
			}
		c20p1305_xor(recvbuf + 12, pos - 12 - 16, stored_key, c20p1305nonce);
		l = pos - 12 - 16;
		for (i=0; i<l && i<rbufmax; i++)
			rbuf[i] = recvbuf[12 + i];
		return (l < rbufmax) ? l : rbufmax;
	}
}


static	W	barcode_prefix_ok(const UB *s)
{
	if (s[0] == 'W' && s[1] == 'I' && s[2] == 'F' && s[3] == 'I' && s[4] == ':')
		return 1;
	if (s[0] == 'C' && s[1] == '2' && s[2] == '0' && s[3] == 'P' && s[4] == ':')
		return 1;
	return 0;
}


/* Collect HID keystrokes into one line, decoded through BOTH keyboard
   layouts in parallel. During the scan window the completed line is a
   barcode: the compile-time default layout's decode is tried first and the
   alternate layout's used as fallback (its prefix check makes the choice
   unambiguous — auto-detection without guessing single characters). After
   the window only the default layout is used, "k="+line, no-reply flag. */
static	void	barcode_char(UB c_def, UB c_alt)
{
	static	UB	linebuf[2 + 256] = {'k', '='};	/* default layout */
	static	UB	linealt[256];			/* alternate layout */
	static	W	pos = 2;
	static	W	posa = 0;

	if (c_def == '\r' || c_def == '\n' || c_alt == '\r' || c_alt == '\n') {
		linebuf[pos] = 0;
		linealt[posa] = 0;
		if (!app_done) {
			if (barcode_prefix_ok(linebuf + 2) || !barcode_prefix_ok(linealt))
				barcode_line(linebuf + 2);
			else {
				lcdtp_sendlogs("(alternate keyboard layout)\n");
				barcode_line(linealt);
			}
		} else if (g_wifi_ok && pos > 2)
			send_request(linebuf, pos, 0, NULL, 0);
		pos = 2;
		posa = 0;
		return;
	}
	if (c_def && pos < (W)sizeof(linebuf) - 1)
		linebuf[pos++] = c_def;
	if (c_alt && posa < (W)sizeof(linealt) - 1)
		linealt[posa++] = c_alt;
}


/* Wi-Fi association; on success later requests are sent on demand from the
   USB loop (HID "k=" lines, printer "p=XX" status polls) via send_request().
   Runs to completion; USB is not serviced meanwhile (accepted). */
static	void	wifi_run(void)
{
	if (stored_ssid[0] == 0 || stored_url[0] == 0) {
		lcdtp_sendlogs("config incomplete (need WIFI: and C20P: scans); skipping wifi.\n");
		return;
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
	g_wifi_ok = 1;
	lcdtp_sendlogs("wifi ready.\n");
}


/* Called from every USB busy-wait via usb_polltask. Counts down the scan
   window on TMR2 (1 kHz), then runs the Wi-Fi phase exactly once. */
static	void	app_polltask(void)
{
	if (in_polltask || app_done)
		return;
	in_polltask = 1;
#ifdef DEBUG_UART_SCAN
	/* Test hook (no barcode reader): during the scan window accept barcode
	   text on U2RX/RB1 too, one keystroke's worth per byte through the US
	   table (a real HID sends keycodes, but debug bytes are already ASCII —
	   feed them to both layout slots as-is). */
	if ((U2STAbits.OERR))
		U2STA = 0x1400;
	if ((U2STAbits.URXDA)) {
		UB ch = U2RXREG;
		lcdtp_sendlogs("<rx:");
		lcdtp_sendlogub(ch);
		lcdtp_sendlogs(">");
		barcode_char(ch, ch);
	}
#endif
	if ((IFS0bits.T2IF)) {
		IFS0bits.T2IF = 0;
		if (window_ms_left > 0)
			window_ms_left--;
	}
	if (window_ms_left == 0) {
		app_done = 1;
		lcdtp_sendlogs("scan window closed\n");
		wifi_run();
		lcdtp_sendlogs("wifi phase done; back to usb host.\n");
	}
	in_polltask = 0;
}


/* One-time application init, before the USB host loop starts. */
static	void	app_init(void)
{
	ANSELA = 0;
	ANSELB = 0;
	CNPUA = 0xffff;
	CNPUB = 0xffff;	/* usb_init() clears CNPUB again for D+/D- */

	/* WROOM on U1: TX=RPB15, RX=RPB13. RB10/RB11 belong to USB. */
	RPB15R = 1;		/* UTX1 */
	U1RXR = 3;		/* RPB13 */
	TRISBbits.TRISB13 = 1;
	U1MODE = 0;
	U1BRG = (10000000 / 115200) - 1;
	U1MODE = 0x8008;	/* enable N81 4(U1BRG + 1) */
	U1STA = 0x1400;

#ifdef DEBUG_UART_SCAN
	/* U2 RX on RB1 so barcode text can be injected over the debug line. */
	U2RXR = 2;		/* RPB1 */
	TRISBbits.TRISB1 = 1;
#endif

	T2CON = 0x0070;		/* 1/256 */
	TMR2 = 0;
	PR2 = 156;		/* 40M / 256 / 1000Hz */
	T2CON = 0x8070;

	SYSKEY = 0;
	SYSKEY = 0xaa996655;
	SYSKEY = 0x556699aa;
	SYSKEY = 0;

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

	/* Bring the WROOM up to a known state before the scan window. */
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
	TMR2 = 0;
	IFS0bits.T2IF = 0;
	lcdtp_sendlogs("scan window open (usb hid)\n");
}


/* ============================================================
 * USB host implementation (pic32mx-usb-minimal usbhost0015.c)
 * ============================================================ */
#define SYS_CLK_HZ       40000000UL
#define CORE_TICK_PER_MS  (SYS_CLK_HZ / 2 / 1000)

/* ============================================================
 * Constants
 * ============================================================ */
#define USB_PID_SETUP  0xD
#define USB_PID_IN     0x9
#define USB_PID_OUT    0x1

#define KVA_TO_PA(v)  ((uint32_t)(v) & 0x1FFFFFFF)

/* ============================================================
 * BDT
 * MLA style: 4 entries (IN Even, IN Odd, OUT Even, OUT Odd).
 * The endpoint number is selected via U1TOK, not the BDT index.
 * ============================================================ */
typedef struct {
	uint32_t stat;
	uint32_t adr;
} BdtEntry;

#define BDT_UOWN   (1u << 7)
#define BDT_DATA1  (1u << 6)
#define BDT_DTS    (1u << 3)
#define BDT_BC(n)  (((uint32_t)(n) & 0x3FF) << 16)

#define BDT_IN_EVEN    0
#define BDT_IN_ODD     1
#define BDT_OUT_EVEN   2
#define BDT_OUT_ODD    3
#define BDT_SIZE       4

static BdtEntry __attribute__((aligned(512))) g_bdt[BDT_SIZE];

/* ============================================================
 * Buffers
 * ============================================================ */
static uint8_t g_ep0_rx_buf[64];
static uint8_t g_ep0_tx_buf[64];
static uint8_t g_bulk_buf[64];
static uint8_t g_hid_buf[8];

/* ============================================================
 * State
 * ============================================================ */
typedef enum {
	USB_DEV_UNKNOWN,
	USB_DEV_PRINTER,
	USB_DEV_KEYBOARD
} UsbDevType;

typedef enum {
	USB_OK = 0,
	USB_ERR_NAK_TIMEOUT,
	USB_ERR_STALL,
	USB_ERR_TIMEOUT
} UsbResult;

#define BULK_RETRY_MAX  100

static UsbDevType g_dev_type     = USB_DEV_UNKNOWN;
static uint8_t    g_dev_addr     = 0;
static uint8_t    g_bulk_ep      = 0;
static uint8_t    g_hid_ep       = 0;
static uint8_t    g_bulk_toggle  = 0;
static uint8_t    g_hid_toggle   = 0;
static uint8_t    g_ep0_toggle   = 0;
static uint8_t    g_is_low_speed = 0;
static uint8_t    g_ep0_max_pkt  = 8;

/* Ping-pong tracking (MLA bfPingPongIn/bfPingPongOut equivalent) */
static uint8_t g_pp_in  = 0;  /* 0 = EVEN next, 1 = ODD next */
static uint8_t g_pp_out = 0;

/* ============================================================
 * Background task hook
 *
 * If non-NULL this function is called repeatedly inside every
 * busy-wait loop (delay, attach wait, token completion wait,
 * detach wait).  The callee must return promptly.
 * ============================================================ */
void (*usb_polltask)(void);

/* ============================================================
 * Utility
 * ============================================================ */
static void poll_call(void)
{
	if (usb_polltask) {
		usb_polltask();
	}
}

int usb_is_detached(void)
{
	return U1IRbits.DETACHIF != 0;
}

static void my_memset(uint8_t *dst, uint8_t val, uint16_t len)
{
	while (len--) {
		*dst++ = val;
	}
}

static void my_memcpy(uint8_t *dst, const uint8_t *src, uint16_t len)
{
	while (len--) {
		*dst++ = *src++;
	}
}

static void delay_init_ms(uint32_t ms)
{
	uint32_t start = _CP0_GET_COUNT();
	uint32_t ticks = ms * CORE_TICK_PER_MS;

	while ((_CP0_GET_COUNT() - start) < ticks) {
		poll_call();
	}
}

static void delay_usbms(uint32_t ms)
{
	while (ms--) {
		U1OTGIR = _U1OTGIR_T1MSECIF_MASK;
		while (!(U1OTGIR & _U1OTGIR_T1MSECIF_MASK)) {
			poll_call();
		}
	}
}

/* ============================================================
 * Ping-pong BDT selection
 * ============================================================ */
static uint8_t pick_bdt_in(void)
{
	uint8_t idx = g_pp_in ? BDT_IN_ODD : BDT_IN_EVEN;
	g_pp_in ^= 1;
	return idx;
}

static uint8_t pick_bdt_out(void)
{
	uint8_t idx = g_pp_out ? BDT_OUT_ODD : BDT_OUT_EVEN;
	g_pp_out ^= 1;
	return idx;
}

static void reset_ping_pong(void)
{
	g_pp_in  = 0;
	g_pp_out = 0;
}

/*
 * U1EP0 bit 6 is RETRYDIS (Retry Disable).
 * Define it manually in case the xc.h version lacks the macro.
 */
#ifndef _U1EP0_RETRYDIS_MASK
#define EP_RETRYDIS   0x40
#else
#define EP_RETRYDIS   _U1EP0_RETRYDIS_MASK
#endif

/* ============================================================
 * Transfer primitives
 * ============================================================ */

/*
 * token_send - MLA _USB_SendToken equivalent.
 *
 * Re-applies U1EP0 and U1ADDR before every token so that
 * low-speed / full-speed switching and any stale register state
 * are handled reliably.
 *
 * pid:        USB_PID_SETUP / IN / OUT
 * ep:         endpoint number (0..15)
 * is_control: 1 enables SETUP (clears EPCONDIS), 0 for bulk/int
 */
static void token_send(uint8_t pid, uint8_t ep, uint8_t is_control)
{
	uint8_t ep_val;
	uint8_t addr_val;

	/*
	 * Control: RETRYDIS=0 (HW auto-retry, NAK absorbed by SIE)
	 * Int/Bulk: RETRYDIS=1 (NAK surfaces immediately for SW retry)
	 */
	ep_val = _U1EP0_EPRXEN_MASK
	       | _U1EP0_EPTXEN_MASK
	       | _U1EP0_EPHSHK_MASK;
	if (!is_control) {
		ep_val |= _U1EP0_EPCONDIS_MASK;
		ep_val |= EP_RETRYDIS;
	}
	if (g_is_low_speed) {
		ep_val |= _U1EP0_LSPD_MASK;
	}
	U1EP0 = ep_val;

	/* U1ADDR: set LSEN for low-speed devices */
	addr_val = g_dev_addr;
	if (g_is_low_speed) {
		addr_val |= 0x80;
	}
	U1ADDR = addr_val;

	/* Issue the token */
	U1TOK = (pid << 4) | (ep & 0x0F);
}

static UsbResult wait_trn(void)
{
	uint32_t timeout = 500000;

	while (!U1IRbits.TRNIF) {
		if (--timeout == 0) {
			return USB_ERR_TIMEOUT;
		}
		if (U1IRbits.DETACHIF) {
			return USB_ERR_TIMEOUT;
		}
		poll_call();
	}
	U1IR = _U1IR_TRNIF_MASK;
	__asm__("nop");
	__asm__("nop");
	return USB_OK;
}

static UsbResult check_pid(uint8_t bdt_idx)
{
	uint8_t pid = (g_bdt[bdt_idx].stat >> 2) & 0x0F;

	if (pid == 0x0A) {
		return USB_ERR_NAK_TIMEOUT;
	}
	if (pid == 0x0E) {
		return USB_ERR_STALL;
	}
	return USB_OK;
}

/* ============================================================
 * USB initialisation
 * ============================================================ */
void usb_init(void)
{
	uint32_t pa;

	my_memset((uint8_t *)g_bdt, 0, sizeof(g_bdt));
	reset_ping_pong();

	/* Disable GPIO / analogue on D+/D- pins (RB10/RB11) */
	ANSELB &= ~((1 << 10) | (1 << 11));
	CNPUB   = 0;   /* clear any stale weak pull-ups */
	CNPDB   = 0;

	/* Disable all USB interrupts and clear flags */
	U1IE    = 0;
	U1IR    = 0xFF;
	U1OTGIE = 0;
	U1OTGIR = 0x7D;
	U1EIE   = 0;
	U1EIR   = 0xFF;

	/* BDT base address */
	pa = KVA_TO_PA((uint32_t)g_bdt);
	U1BDTP1 = (pa >> 8)  & 0xFF;
	U1BDTP2 = (pa >> 16) & 0xFF;
	U1BDTP3 = (pa >> 24) & 0xFF;

	/* HOSTEN + PPBRST sequence */
	U1CON = _U1CON_HOSTEN_MASK;
	U1CON = _U1CON_HOSTEN_MASK | _U1CON_PPBRST_MASK;
	U1CON = _U1CON_HOSTEN_MASK;

	/* D+/D- pull-downs + VBUS on (separate write) */
	U1OTGCON = _U1OTGCON_DPPULDWN_MASK | _U1OTGCON_DMPULDWN_MASK;
	U1OTGCON |= _U1OTGCON_VBUSON_MASK;

	/* Full ping-pong */
	U1CNFG1 = 0x02;

	U1ADDR = 0;
	U1EP0  = _U1EP0_EPCONDIS_MASK
	       | _U1EP0_EPRXEN_MASK
	       | _U1EP0_EPTXEN_MASK
	       | _U1EP0_EPHSHK_MASK;
	/* RETRYDIS is set per-transfer inside token_send() */
	U1SOF = 0x4A;

	/* Power on the USB module last */
	U1PWRCbits.USBPWR = 1;
	delay_init_ms(10);
}

/* ============================================================
 * Attach wait and bus reset
 * ============================================================ */
void usb_wait_attach_and_reset(void)
{
	while (!U1IRbits.ATTACHIF) {
		poll_call();
	}
	U1IR = _U1IR_ATTACHIF_MASK;

	delay_usbms(200);

	if (!U1CONbits.JSTATE) {
		g_is_low_speed = 1;
	} else {
		g_is_low_speed = 0;
	}

	/* Re-reset ping-pong (both HW and SW) */
	U1CONbits.PPBRST = 1;
	U1CONbits.PPBRST = 0;
	reset_ping_pong();

	/* Bus reset: assert for 50 ms */
	U1CONbits.USBRST = 1;
	delay_usbms(50);
	U1CONbits.USBRST = 0;

	/* MLA order: enable SOF immediately after reset release */
	U1CONbits.SOFEN = 1;

	/* Reset recovery: low-speed devices need ~100 ms */
	delay_usbms(100);

	g_dev_addr  = 0;
	g_ep0_toggle = 0;

	U1IR = _U1IR_DETACHIF_MASK;
}

/* ============================================================
 * Control transfer primitives (ping-pong aware)
 * ============================================================ */
static void ctrl_setup(uint8_t *pkt8)
{
	uint8_t idx = pick_bdt_out();

	my_memcpy(g_ep0_tx_buf, pkt8, 8);

	g_bdt[idx].adr  = KVA_TO_PA((uint32_t)g_ep0_tx_buf);
	g_bdt[idx].stat = BDT_UOWN | BDT_DTS | BDT_BC(8);

	token_send(USB_PID_SETUP, 0, 1);
	wait_trn();
	g_ep0_toggle = 1;
}

static uint16_t ctrl_in(uint8_t *data, uint16_t max_len)
{
	uint16_t total = 0;
	uint16_t chunk_len;
	uint16_t rx_len;
	uint8_t  idx;

	while (total < max_len) {
		chunk_len = max_len - total;
		if (chunk_len > g_ep0_max_pkt) {
			chunk_len = g_ep0_max_pkt;
		}

		idx = pick_bdt_in();
		g_bdt[idx].adr  = KVA_TO_PA((uint32_t)g_ep0_rx_buf);
		g_bdt[idx].stat = BDT_UOWN | BDT_DTS
		                | (g_ep0_toggle ? BDT_DATA1 : 0)
		                | BDT_BC(chunk_len);

		token_send(USB_PID_IN, 0, 1);
		if (wait_trn() != USB_OK) {
			break;
		}

		rx_len = (g_bdt[idx].stat >> 16) & 0x3FF;
		my_memcpy(data + total, g_ep0_rx_buf, rx_len);
		total += rx_len;
		g_ep0_toggle ^= 1;

		/* Short packet terminates the transfer */
		if (rx_len < chunk_len) {
			break;
		}
	}
	return total;
}

static void ctrl_out_zlp(void)
{
	uint8_t idx = pick_bdt_out();

	g_bdt[idx].adr  = KVA_TO_PA((uint32_t)g_ep0_tx_buf);
	g_bdt[idx].stat = BDT_UOWN | BDT_DTS | BDT_DATA1 | BDT_BC(0);

	token_send(USB_PID_OUT, 0, 1);
	wait_trn();
}

static void ctrl_in_zlp(void)
{
	uint8_t idx = pick_bdt_in();

	g_bdt[idx].adr  = KVA_TO_PA((uint32_t)g_ep0_rx_buf);
	g_bdt[idx].stat = BDT_UOWN | BDT_DTS | BDT_DATA1 | BDT_BC(0);

	token_send(USB_PID_IN, 0, 1);
	wait_trn();
}

/* ============================================================
 * Standard requests
 * ============================================================ */
static uint16_t usb_get_descriptor(uint8_t type, uint8_t idx,
                                   uint8_t *buf, uint16_t len)
{
	uint8_t  setup[8];
	uint16_t rx_len;

	setup[0] = 0x80; setup[1] = 0x06;
	setup[2] = idx;  setup[3] = type;
	setup[4] = 0x00; setup[5] = 0x00;
	setup[6] = (uint8_t)(len & 0xFF);
	setup[7] = (uint8_t)(len >> 8);

	ctrl_setup(setup);
	rx_len = ctrl_in(buf, len);
	ctrl_out_zlp();
	return rx_len;
}

static void usb_set_address(uint8_t addr)
{
	uint8_t setup[8];

	setup[0] = 0x00; setup[1] = 0x05;
	setup[2] = addr; setup[3] = 0x00;
	setup[4] = 0x00; setup[5] = 0x00;
	setup[6] = 0x00; setup[7] = 0x00;

	ctrl_setup(setup);
	ctrl_in_zlp();
	delay_usbms(2);

	g_dev_addr = addr;
}

static void usb_set_configuration(uint8_t cfg_val)
{
	uint8_t setup[8];

	setup[0] = 0x00; setup[1] = 0x09;
	setup[2] = cfg_val; setup[3] = 0x00;
	setup[4] = 0x00; setup[5] = 0x00;
	setup[6] = 0x00; setup[7] = 0x00;

	ctrl_setup(setup);
	ctrl_in_zlp();
}

static void usb_set_interface(uint8_t if_num, uint8_t alt_num)
{
	uint8_t setup[8];

	setup[0] = 0x01; setup[1] = 0x0B;
	setup[2] = alt_num; setup[3] = 0x00;
	setup[4] = if_num;  setup[5] = 0x00;
	setup[6] = 0x00; setup[7] = 0x00;

	ctrl_setup(setup);
	ctrl_in_zlp();
}

/* Printer class GET_PORT_STATUS: one byte, bit5 paper-out, bit4
   selected, bit3 no-error (centronics polarity). Returns 0..255 on
   success, -1 when the device does not answer with a full byte. */
static int usb_printer_get_port_status(void)
{
	uint8_t setup[8];
	uint8_t status;

	setup[0] = 0xA1; setup[1] = 0x01;
	setup[2] = 0x00; setup[3] = 0x00;
	setup[4] = 0x00; setup[5] = 0x00;
	setup[6] = 0x01; setup[7] = 0x00;

	ctrl_setup(setup);
	if (ctrl_in(&status, 1) != 1) {
		return -1;
	}
	ctrl_out_zlp();
	return status;
}

/* ============================================================
 * Configuration descriptor parser
 * ============================================================ */
static UsbDevType parse_config_desc(uint8_t *buf, uint16_t len)
{
	UsbDevType dev_type = USB_DEV_UNKNOWN;
	uint16_t i = 0;
	uint8_t  desc_len;
	uint8_t  desc_type;
	uint8_t  cls;
	uint8_t  subcls;
	uint8_t  proto;
	uint8_t  alt_num;
	uint8_t  ep_addr;
	uint8_t  attr;
	uint8_t  in_target = 0;

	g_bulk_ep = 0;
	g_hid_ep  = 0;

	while (i < len) {
		desc_len  = buf[i];
		desc_type = buf[i + 1];

		if (desc_type == 0x04) {  /* Interface descriptor */
			alt_num = buf[i + 3];
			cls     = buf[i + 5];
			subcls  = buf[i + 6];
			proto   = buf[i + 7];

			/*
			 * Accept only the first matching interface
			 * at alternate setting 0.
			 */
			if (alt_num == 0 && dev_type == USB_DEV_UNKNOWN) {
				if (cls == 0x07) {
					dev_type  = USB_DEV_PRINTER;
					in_target = 1;
				} else if (cls == 0x03
				           && subcls == 0x01
				           && proto == 0x01) {
					dev_type  = USB_DEV_KEYBOARD;
					in_target = 1;
				} else {
					in_target = 0;
				}
			} else {
				in_target = 0;
			}
		}

		if (desc_type == 0x05 && in_target) {  /* Endpoint */
			ep_addr = buf[i + 2];
			attr    = buf[i + 3];

			if (dev_type == USB_DEV_PRINTER) {
				if ((ep_addr & 0x80) == 0x00
				    && (attr & 0x03) == 0x02) {
					if (g_bulk_ep == 0) {
						g_bulk_ep = ep_addr & 0x0F;
					}
				}
			} else if (dev_type == USB_DEV_KEYBOARD) {
				if ((ep_addr & 0x80) == 0x80
				    && (attr & 0x03) == 0x03) {
					if (g_hid_ep == 0) {
						g_hid_ep = ep_addr & 0x0F;
					}
				}
			}
		}

		if (desc_len == 0) {
			break;
		}
		i += desc_len;
	}
	return dev_type;
}

static void hid_set_boot_protocol(void)
{
	uint8_t setup[8];

	setup[0] = 0x21; setup[1] = 0x0B;
	setup[2] = 0x00; setup[3] = 0x00;
	setup[4] = 0x00; setup[5] = 0x00;
	setup[6] = 0x00; setup[7] = 0x00;

	ctrl_setup(setup);
	ctrl_in_zlp();
}

/* ============================================================
 * Enumeration
 * ============================================================ */
void usb_enumerate(void)
{
	uint8_t  buf[256];
	uint16_t total_len;

	my_memset(buf, 0, sizeof(buf));
	g_ep0_max_pkt = 8;

	usb_get_descriptor(0x01, 0, buf, 8);

	g_ep0_max_pkt = buf[7];
	if (g_ep0_max_pkt == 0 || g_ep0_max_pkt > 64) {
		g_ep0_max_pkt = 8;
	}

	usb_set_address(0x01);

	usb_get_descriptor(0x01, 0, buf, 18);

	usb_get_descriptor(0x02, 0, buf, 9);

	total_len = buf[2] | ((uint16_t)buf[3] << 8);
	usb_get_descriptor(0x02, 0, buf, total_len);

	g_dev_type = parse_config_desc(buf, total_len);

	usb_set_configuration(buf[5]);

	if (g_dev_type == USB_DEV_PRINTER) {
		usb_set_interface(0, 0);

		/*
		 * Enable the EP1 register for bulk transfers.
		 * The endpoint number is still selected via U1TOK,
		 * but the EPn register must also be enabled in host
		 * mode.
		 */
		U1EP1 = _U1EP1_EPTXEN_MASK
		      | _U1EP1_EPRXEN_MASK
		      | _U1EP1_EPHSHK_MASK;
		g_bulk_toggle = 0;
	} else if (g_dev_type == USB_DEV_KEYBOARD) {
		hid_set_boot_protocol();
		U1EP1 = _U1EP1_EPRXEN_MASK | _U1EP1_EPHSHK_MASK;
		g_hid_toggle = 0;
	}
}

/* ============================================================
 * Post-detach full reset
 * ============================================================ */
static void usb_reset_state(void)
{
	g_dev_type     = USB_DEV_UNKNOWN;
	g_dev_addr     = 0;
	g_bulk_ep      = 0;
	g_hid_ep       = 0;
	g_bulk_toggle  = 0;
	g_hid_toggle   = 0;
	g_ep0_toggle   = 0;
	g_is_low_speed = 0;
	g_ep0_max_pkt  = 8;

	U1IE    = 0;
	U1OTGIE = 0;
	U1EIE   = 0;
	U1CON   = 0;
	U1PWRCbits.USBPWR = 0;
	delay_init_ms(2);

	my_memset((uint8_t *)g_bdt, 0, sizeof(g_bdt));

	usb_init();
}

/* ============================================================
 * Bulk OUT transfer (shares the BDT with EP0; endpoint number
 * is selected via U1TOK)
 * ============================================================ */
UsbResult usb_bulk_write(uint8_t *data, uint16_t len)
{
	uint16_t  offset = 0;
	uint16_t  chunk_len;
	uint8_t   retry_count;
	uint8_t   idx;
	UsbResult result;

	while (offset < len) {
		chunk_len = len - offset;
		if (chunk_len > 64) {
			chunk_len = 64;
		}
		retry_count = 0;

		my_memcpy(g_bulk_buf, data + offset, chunk_len);

		do {
			idx = pick_bdt_out();
			g_bdt[idx].adr  = KVA_TO_PA((uint32_t)g_bulk_buf);
			g_bdt[idx].stat = BDT_UOWN | BDT_DTS
			                | (g_bulk_toggle ? BDT_DATA1 : 0)
			                | BDT_BC(chunk_len);

			token_send(USB_PID_OUT, g_bulk_ep, 0);

			result = wait_trn();
			if (result == USB_ERR_TIMEOUT) {
				return USB_ERR_TIMEOUT;
			}

			result = check_pid(idx);

			if (result == USB_ERR_STALL) {
				return USB_ERR_STALL;
			}

			if (result == USB_ERR_NAK_TIMEOUT) {
				retry_count++;
				if (retry_count >= BULK_RETRY_MAX) {
					return USB_ERR_NAK_TIMEOUT;
				}
				delay_usbms(1);
				if (U1IRbits.DETACHIF) {
					return USB_ERR_TIMEOUT;
				}
			}
		} while (result == USB_ERR_NAK_TIMEOUT);

		g_bulk_toggle ^= 1;
		offset += chunk_len;
	}
	return USB_OK;
}

/* ============================================================
 * Interrupt IN transfer
 * ============================================================ */
typedef struct {
	uint8_t modifier;
	uint8_t reserved;
	uint8_t keycode[6];
} HidKbReport;

static int usb_interrupt_in(void)
{
	uint32_t timeout;
	uint8_t  pid;
	uint8_t  idx;

	idx = pick_bdt_in();
	g_bdt[idx].adr  = KVA_TO_PA((uint32_t)g_hid_buf);
	g_bdt[idx].stat = BDT_UOWN | BDT_DTS
	                | (g_hid_toggle ? BDT_DATA1 : 0)
	                | BDT_BC(8);

	token_send(USB_PID_IN, g_hid_ep, 0);

	/*
	 * RETRYDIS is set, so a NAK raises TRNIF immediately.
	 * A short timeout is sufficient.
	 */
	timeout = 10000;
	while (!U1IRbits.TRNIF) {
		if (--timeout == 0) {
			return -1;
		}
		if (U1IRbits.DETACHIF) {
			return -1;
		}
		poll_call();
	}
	U1IR = _U1IR_TRNIF_MASK;

	pid = (g_bdt[idx].stat >> 2) & 0x0F;
	if (pid == 0x0A) {
		return 0;  /* NAK - no data available */
	}

	g_hid_toggle ^= 1;
	return 1;
}

/* ============================================================
 * Keycode to ASCII (US layout)
 * ============================================================ */
static const char keycode_to_ascii[58] = {
	0,    0,    0,    0,   'a', 'b', 'c', 'd',
	'e',  'f',  'g',  'h', 'i', 'j', 'k', 'l',
	'm',  'n',  'o',  'p', 'q', 'r', 's', 't',
	'u',  'v',  'w',  'x', 'y', 'z', '1', '2',
	'3',  '4',  '5',  '6', '7', '8', '9', '0',
	'\n', 0,   '\b', '\t', ' ', '-', '=', '[',
	']',  '\\', 0,    ';', '\'', '`', ',', '.',
	'/',  0,
};

static const char keycode_to_ascii_shift[58] = {
	0,    0,    0,    0,   'A', 'B', 'C', 'D',
	'E',  'F',  'G',  'H', 'I', 'J', 'K', 'L',
	'M',  'N',  'O',  'P', 'Q', 'R', 'S', 'T',
	'U',  'V',  'W',  'X', 'Y', 'Z', '!', '@',
	'#',  '$',  '%',  '^', '&', '*', '(', ')',
	'\n', 0,   '\b', '\t', ' ', '_', '+', '{',
	'}',  '|',  0,    ':', '"', '~', '<', '>',
	'?',  0,
};

/* JIS (JP 106/109) layout tables. Letters and digits match US; the symbol
   block differs. Keycode 0x87 (International1, the "Ro" key) is JIS-only:
   '\\' unshifted, '_' shifted — handled separately below. */
static const char keycode_to_ascii_jis[58] = {
	0,    0,    0,    0,   'a', 'b', 'c', 'd',
	'e',  'f',  'g',  'h', 'i', 'j', 'k', 'l',
	'm',  'n',  'o',  'p', 'q', 'r', 's', 't',
	'u',  'v',  'w',  'x', 'y', 'z', '1', '2',
	'3',  '4',  '5',  '6', '7', '8', '9', '0',
	'\n', 0,   '\b', '\t', ' ', '-', '^', '@',
	'[',  ']',  ']',  ';', ':', 0,   ',', '.',
	'/',  0,
};

static const char keycode_to_ascii_jis_shift[58] = {
	0,    0,    0,    0,   'A', 'B', 'C', 'D',
	'E',  'F',  'G',  'H', 'I', 'J', 'K', 'L',
	'M',  'N',  'O',  'P', 'Q', 'R', 'S', 'T',
	'U',  'V',  'W',  'X', 'Y', 'Z', '!', '"',
	'#',  '$',  '%',  '&', '\'', '(', ')', 0,
	'\n', 0,   '\b', '\t', ' ', '=', '~', '`',
	'{',  '}',  '}',  '+', '*', 0,   '<', '>',
	'?',  0,
};

/*
	Keyboard layout. The compile-time default is JP (JIS); build with
	-DHID_LAYOUT_US for US. During the barcode scan window every keystroke
	is decoded through BOTH layouts in parallel and barcode_char() picks
	the line whose prefix validates — automatic and unambiguous. After the
	window (the "k=" phase) only the default layout is used.
*/
#ifdef HID_LAYOUT_US
#define HID_LAYOUT_DEFAULT_JIS	0
#else
#define HID_LAYOUT_DEFAULT_JIS	1
#endif

static char keycode_to_char(uint8_t keycode, uint8_t modifier, uint8_t jis)
{
	/* JIS-only keys: International1 "Ro" and International3 Yen. */
	if (keycode == 0x87)
		return jis ? ((modifier & 0x22) ? '_' : '\\') : 0;
	if (keycode == 0x89)
		return jis ? ((modifier & 0x22) ? '|' : '\\') : 0;
	if (keycode >= sizeof(keycode_to_ascii)) {
		return 0;
	}
	/* Barcode scans carry ':', ';', '&', '?', '_', uppercase, etc., so
	   shift must map the full table, not just letters. */
	if (jis)
		return (modifier & 0x22) ? keycode_to_ascii_jis_shift[keycode]
		                         : keycode_to_ascii_jis[keycode];
	return (modifier & 0x22) ? keycode_to_ascii_shift[keycode]
	                         : keycode_to_ascii[keycode];
}


/* ============================================================
 * Main — USB host loop (from usbhost0015.c) with barcode hooks
 * ============================================================ */
int main(void)
{
	HidKbReport  prev;
	HidKbReport *rep;
	int          ret;
	int          i;
	int          j;
	int          already;
	uint8_t      kc;
	char         c;

	app_init();
	usb_polltask = app_polltask;

	usb_init();

	while (1) {
		usb_wait_attach_and_reset();

		usb_enumerate();

		if (g_dev_type == USB_DEV_PRINTER) {
			/*
			 * Poll the server with a "p=XX" request every 2 s, where
			 * XX is the printer's GET_PORT_STATUS byte in hex (bare
			 * "p=" when the status read fails), and feed any reply
			 * body straight to the printer. A non-empty reply skips
			 * the wait so queued data drains at full rate.
			 */
			while (!usb_is_detached()) {
				if (app_done && g_wifi_ok) {
					static const UB *bin2hex = (const UB *)"0123456789abcdef";
					/* send_request advertises RECVBUF_SIZE via "s",
					   so accept the largest body that can carry. */
					static uint8_t prbuf[RECVBUF_SIZE - 12 - 16];
					UB  preq[4];
					W   plen;
					int pst;
					W n;

					preq[0] = 'p';
					preq[1] = '=';
					plen = 2;
					pst = usb_printer_get_port_status();
					if (pst >= 0) {
						preq[2] = bin2hex[(pst >> 4) & 0xf];
						preq[3] = bin2hex[pst & 0xf];
						plen = 4;
					}

					n = send_request(preq, plen, 1,
					                 (UB *)prbuf, (W)sizeof(prbuf));
					if (n > 0) {
						usb_bulk_write(prbuf, (uint16_t)n);
						continue;
					}
					delay_usbms(2000);
				} else {
					poll_call();
				}
			}
		} else if (g_dev_type == USB_DEV_KEYBOARD) {
			prev.modifier = 0;
			prev.reserved = 0;
			for (i = 0; i < 6; i++) {
				prev.keycode[i] = 0;
			}

			while (!usb_is_detached()) {
				ret = usb_interrupt_in();
				delay_usbms(10);

				if (ret <= 0) {
					continue;
				}

				rep = (HidKbReport *)g_hid_buf;

				for (i = 0; i < 6; i++) {
					kc = rep->keycode[i];
					if (kc == 0) {
						continue;
					}

					already = 0;
					for (j = 0; j < 6; j++) {
						if (prev.keycode[j] == kc) {
							already = 1;
							break;
						}
					}
					if (already) {
						continue;
					}

					c = keycode_to_char(kc, rep->modifier,
					                    HID_LAYOUT_DEFAULT_JIS);
					{
						char c2 = keycode_to_char(kc, rep->modifier,
						                          !HID_LAYOUT_DEFAULT_JIS);
						if (c || c2) {
							barcode_char((UB)c, (UB)c2);
						}
					}
				}
				prev = *rep;
			}
		} else {
			/* Unknown class: idle until detach */
			while (!usb_is_detached()) {
				poll_call();
			}
		}

		usb_reset_state();
		delay_init_ms(200);
	}

	return 0;
}

