
/*
	Smallest touchpanel UI https://github.com/paijp/smallest-touchpanel-ui

	Copyright (c) 2022-2024 paijp

	This software is released under the Apache 2.0 license.
	http://www.apache.org/licenses/
*/

#include	"basic.h"


	/* lcdtp.c */

#define	LCD_W	240
#define	LCD_H	320

extern	UW	lcdtp_flip;
#define	LCDTP_FLIP_X	1
#define	LCDTP_FLIP_Y	2

extern	void	(*lcdtp_polltask)();

extern	const	struct	lcdtp_font_struct {
	struct	lcdtp_font_attr_struct {
		const	struct	lcdtp_font_struct	*fallback;
	} attr;
	unsigned char	font[];
} lcdtp_font12h;

void	dly_tsk(W ms);
void	gfil_rec(W l, W t, W r, W b, UW color16);
void	gdra_stp(W x, W y, UW color16, UW bgcolor16, const struct lcdtp_font_struct *font, const UB *s);
W	gget_stw(const struct lcdtp_font_struct *font, const UB *s);
UW	gettp();
void	init_lcdtp();

void	lcdtp_sendlogc(W c);
void	lcdtp_sendlogs(const char *s);
void	lcdtp_sendlogdec(W v);
void	lcdtp_sendlogun(UW v);
void	lcdtp_sendlogub(UW v);
void	lcdtp_sendloguh(UW v);
void	lcdtp_sendloguw(UW v);


#define	TPLIB_CMD_MASK	0xff000000
#define	TPLIB_CMD_NULL	0
#define	TPLIB_CMD_PRESS	0x10000000		/* 10xxxyyy */
#define	TPLIB_CMD_PRESSING	0x11000000		/* 10xxxyyy */

#define	LCDTP_FONT12	(NULL)


