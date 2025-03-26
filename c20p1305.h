/*
	Single file chacha20poly1305 https://github.com/paijp/single-file-chacha20poly1305
	
	License: MIT or PUBLIC DOMAIN.
*/

#ifdef	__unix__		/* int=32bit */
typedef	signed char	B;
typedef	short	H;
typedef	int	W;
typedef	unsigned char	UB;
typedef	unsigned short	UH;
typedef	unsigned int	UW;
#else		/* long=32bit */
typedef	signed char	B;
typedef	short	H;
typedef	long	W;
typedef	unsigned char	UB;
typedef	unsigned short	UH;
typedef	unsigned long	UW;
#endif

#ifndef	NULL
#define	NULL	((void*)0)
#endif


/* from https://github.com/floodyberry/poly1305-donna */

#define POLY1305_BLOCK_SIZE 16

struct	poly1305_state_internal_struct {
	UB	buffer[POLY1305_BLOCK_SIZE];
	W	leftover;
	UB	h[17];
	UB	r[17];
	UB	pad[17];
	UB	final;
};


static	void	poly1305_init(struct poly1305_state_internal_struct *state, const UB key[32])
{
	W	i;

	state->leftover = 0;

	/* h = 0 */
	for (i=0; i<17; i++)
		state->h[i] = 0;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	state->r[ 0] = key[ 0] & 0xff;
	state->r[ 1] = key[ 1] & 0xff;
	state->r[ 2] = key[ 2] & 0xff;
	state->r[ 3] = key[ 3] & 0x0f;
	state->r[ 4] = key[ 4] & 0xfc;
	state->r[ 5] = key[ 5] & 0xff;
	state->r[ 6] = key[ 6] & 0xff;
	state->r[ 7] = key[ 7] & 0x0f;
	state->r[ 8] = key[ 8] & 0xfc;
	state->r[ 9] = key[ 9] & 0xff;
	state->r[10] = key[10] & 0xff;
	state->r[11] = key[11] & 0x0f;
	state->r[12] = key[12] & 0xfc;
	state->r[13] = key[13] & 0xff;
	state->r[14] = key[14] & 0xff;
	state->r[15] = key[15] & 0x0f;
	state->r[16] = 0;

	/* save pad for later */
	for (i=0; i<16; i++)
		state->pad[i] = key[i + 16];
	state->pad[16] = 0;

	state->final = 0;
}


static	void	poly1305_add(UB h[17], const UB c[17])
{
	UH	u;
	W	i;
	
	u = 0;
	for (i=0; i<17; i++) {
		u += (UH)h[i] + (UH)c[i];
		h[i] = (UB)u & 0xff;
		u >>= 8;
	}
}


static	void	poly1305_squeeze(UB h[17], UW hr[17])
{
	UW	u;
	W	i;
	
	u = 0;
	for (i=0; i<16; i++) {
		u += hr[i];
		h[i] = (UB)u & 0xff;
		u >>= 8;
	}
	u += hr[16];
	h[16] = (UB)u & 0x03;
	u >>= 2;
	u += (u << 2); /* u *= 5; */
	for (i=0; i<16; i++) {
		u += h[i];
		h[i] = (UB)u & 0xff;
		u >>= 8;
	}
	h[16] += (UB)u;
}


static	void	poly1305_freeze(UB h[17])
{
	static	const	UB	minusp[17] = {
		0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xfc
	};
	UB	horig[17], negative;
	W	i;

	/* compute h + -p */
	for (i=0; i<17; i++)
		horig[i] = h[i];
	poly1305_add(h, minusp);

	/* select h if h < p, or h + -p if h >= p */
	negative = -(h[16] >> 7);
	for (i=0; i<17; i++)
		h[i] ^= negative & (horig[i] ^ h[i]);
}


static	void	poly1305_blocks(struct poly1305_state_internal_struct *state, const UB *m, W bytes)
{
	UB	hibit;
	
	hibit  = state->final ^ 1; /* 1 << 128 */
	while (bytes >= POLY1305_BLOCK_SIZE) {
		UW	hr[17], u;
		UB	c[17];
		W	i, j;

		/* h += m */
		for (i=0; i<16; i++)
			c[i] = m[i];
		c[16] = hibit;
		poly1305_add(state->h, c);

		/* h *= r */
		for (i=0; i<17; i++) {
			u = 0;
			for (j=0; j<=i ; j++)
				u += (UH)state->h[j] * state->r[i - j];
			for (j=i+1; j<17; j++) {
				UW	v;
				
				v = (UH)state->h[j] * state->r[i + 17 - j];
				v = ((v << 8) + (v << 6)); /* v *= (5 << 6); */
				u += v;
			}
			hr[i] = u;
		}

		/* (partial) h %= p */
		poly1305_squeeze(state->h, hr);

		m += POLY1305_BLOCK_SIZE;
		bytes -= POLY1305_BLOCK_SIZE;
	}
}


static	__attribute__((noinline))	void	poly1305_finish(struct poly1305_state_internal_struct *state, UB mac[16])
{
	W	i;

	/* process the remaining block */
	if ((state->leftover)) {
		i = state->leftover;
		state->buffer[i++] = 1;
		while (i < POLY1305_BLOCK_SIZE)
			state->buffer[i++] = 0;
		state->final = 1;
		poly1305_blocks(state, state->buffer, POLY1305_BLOCK_SIZE);
	}

	/* fully reduce h */
	poly1305_freeze(state->h);

	/* h = (h + pad) % (1 << 128) */
	poly1305_add(state->h, state->pad);
	for (i=0; i<16; i++)
		mac[i] = state->h[i];

	/* zero out the state */
	for (i=0; i<17; i++)
		state->h[i] = 0;
	for (i=0; i<17; i++)
		state->r[i] = 0;
	for (i=0; i<17; i++)
		state->pad[i] = 0;
}


static	void	poly1305_update(struct poly1305_state_internal_struct *state, const UB *m, W bytes)
{
	W	i;

	/* handle leftover */
	if ((state->leftover)) {
		W	want;
		
		want = POLY1305_BLOCK_SIZE - state->leftover;
		if (want > bytes)
			want = bytes;
		for (i=0; i<want; i++)
			state->buffer[state->leftover + i] = m[i];
		bytes -= want;
		m += want;
		state->leftover += want;
		if (state->leftover < POLY1305_BLOCK_SIZE)
			return;
		poly1305_blocks(state, state->buffer, POLY1305_BLOCK_SIZE);
		state->leftover = 0;
	}

	/* process full blocks */
	if (bytes >= POLY1305_BLOCK_SIZE) {
		W	want;

		want = bytes & ~(POLY1305_BLOCK_SIZE - 1);
		poly1305_blocks(state, m, want);
		m += want;
		bytes -= want;
	}

	/* store leftover */
	if (bytes) {
		for (i=0; i<bytes; i++)
			state->buffer[state->leftover + i] = m[i];
		state->leftover += bytes;
	}
}


#define	CHACHA20_ROTL(a,b)	(((a) << (b)) | ((a) >> (32 - (b))))
#define	CHACHA20_QR(a, b, c, d) (		\
	a += b, d ^= a, d = CHACHA20_ROTL(d,16),	\
	c += d, b ^= c, b = CHACHA20_ROTL(b,12),	\
	a += b, d ^= a, d = CHACHA20_ROTL(d, 8),	\
	c += d, b ^= c, b = CHACHA20_ROTL(b, 7))
#define	CHACHA20_ROUNDS	20


static	void	chacha20_block(UB out[64], UB const key[32], UB const counter[4], UB const nonce[12])
{
	static	UW	in[16];
	static	UW	x[16];
	const	UB	*p;
	UB	*q;
	UW	*r;
	W	i;
	
	r = in;
	*(r++) = 0x61707865;
	*(r++) = 0x3320646e;
	*(r++) = 0x79622d32;
	*(r++) = 0x6b206574;
	p = key;
	for (i=0; i<8; i++) {
		UW	v;
		
		v = *(p++);
		v |= ((UW)*(p++)) << 8;
		v |= ((UW)*(p++)) << 16;
		v |= ((UW)*(p++)) << 24;
		*(r++) = v;
	}
	p = counter;
	for (i=0; i<1; i++) {
		UW	v;
		
		v = *(p++);
		v |= ((UW)*(p++)) << 8;
		v |= ((UW)*(p++)) << 16;
		v |= ((UW)*(p++)) << 24;
		*(r++) = v;
	}
	p = nonce;
	for (i=0; i<3; i++) {
		UW	v;
		
		v = *(p++);
		v |= ((UW)*(p++)) << 8;
		v |= ((UW)*(p++)) << 16;
		v |= ((UW)*(p++)) << 24;
		*(r++) = v;
	}
	for (i=0; i<16; i++)
		x[i] = in[i];
	for (i=0; i<CHACHA20_ROUNDS; i+=2) {
		CHACHA20_QR(x[0], x[4], x[8], x[12]);
		CHACHA20_QR(x[1], x[5], x[9], x[13]);
		CHACHA20_QR(x[2], x[6], x[10], x[14]);
		CHACHA20_QR(x[3], x[7], x[11], x[15]);
		
		CHACHA20_QR(x[0], x[5], x[10], x[15]);
		CHACHA20_QR(x[1], x[6], x[11], x[12]);
		CHACHA20_QR(x[2], x[7], x[8], x[13]);
		CHACHA20_QR(x[3], x[4], x[9], x[14]);
	}
	q = out;
	for (i=0; i<16; i++) {
		UW	v;
		
		v = x[i] + in[i];
		*(q++) = (v & 0xff);
		*(q++) = ((v >> 8) & 0xff);
		*(q++) = ((v >> 16) & 0xff);
		*(q++) = ((v >> 24) & 0xff);
	}
}


static	void	c20p1305_xor(UB *buf, W size, const UB key[32], const UB nonce[12])
{
	static	UB	counter[4];
	static	UB	out[64];
	W	pos;
	
	for (pos=0; pos<size; pos++) {
		if ((pos & 0x3f) == 0) {
			W	i;
			
			i = (pos >> 6) + 1;		/* counter: 1- */
			counter[0] = i & 0xff;
			counter[1] = (i >> 8) & 0xff;
			counter[2] = (i >> 16) & 0xff;
			counter[3] = (i >> 24) & 0xff;
			chacha20_block(out, key, counter, nonce);
		}
		buf[pos] ^= out[pos & 0x3f];
	}
}


static	void	c20p1305_mac(UB mac[16], const UB *aad, W aadsize, const UB *buf, W bufsize, const UB key[32], const UB nonce[12])
{
	static	struct	poly1305_state_internal_struct	state;
	static	const	UB	zero16[16] = {0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0};
	static	UB	out[64];
	W	i;
	
	chacha20_block(out, key, zero16, nonce);
	poly1305_init(&state, out);
	if (aad == NULL)
		aadsize = 0;
	if (aadsize > 0) {
		poly1305_update(&state, aad, aadsize);
		if ((i = aadsize & 0xf))
			poly1305_update(&state, zero16, 16 - i);
	}
	if (buf == NULL)
		bufsize = 0;
	if (bufsize > 0) {
		poly1305_update(&state, buf, bufsize);
		if ((i = bufsize & 0xf))
			poly1305_update(&state, zero16, 16 - i);
	}
	{
		static	UB	len[8] = {0, 0, 0, 0,  0, 0, 0, 0};
		
		len[0] = aadsize & 0xff;
		len[1] = (aadsize >> 8) & 0xff;
		len[2] = (aadsize >> 16) & 0xff;
		len[3] = (aadsize >> 24) & 0xff;
		poly1305_update(&state, len, 8);
		
		len[0] = bufsize & 0xff;
		len[1] = (bufsize >> 8) & 0xff;
		len[2] = (bufsize >> 16) & 0xff;
		len[3] = (bufsize >> 24) & 0xff;
		poly1305_update(&state, len, 8);
	}
	poly1305_finish(&state, mac);
}


