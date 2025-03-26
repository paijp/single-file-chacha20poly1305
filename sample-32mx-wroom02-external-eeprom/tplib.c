
/*
	Smallest touchpanel UI https://github.com/paijp/smallest-touchpanel-ui

	Copyright (c) 2022-2024 paijp

	This software is released under the Apache 2.0 license.
	http://www.apache.org/licenses/
*/

#include	"tplib.h"


const	struct	tplib_font_struct	*tplib_systemfont = LCDTP_FONT12;

static	char	*log_funcname = NULL;
static	W	(*log_fn)(struct tplib_parts_struct *p, UW cmd) = NULL;
static	char	*log_sha1 = NULL;


W	tplib_parts_fill(struct tplib_parts_struct *p, UW cmd)
{
	switch (cmd & TPLIB_CMD_MASK) {
		default:
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_REDRAW:
			break;
	}
	gfil_rec(p->left, p->top, p->left + p->width, p->top + p->height, p->par);
	return TPLIB_CONTINUE;
}


W	tplib_parts_text(struct tplib_parts_struct *p, UW cmd)
{
	W	ret;
	
	switch (cmd & TPLIB_CMD_MASK) {
		default:
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_REDRAWPART:
			gfil_rec(p->left, p->top, p->left + p->width, p->top + p->height, TPLIB_BGCOLOR);
		case	TPLIB_CMD_REDRAW:
			break;
	}
	
	if ((p->fn))
		if ((ret = p->fn(p, cmd)) != TPLIB_CONTINUE)
			return ret;
	
	gdra_stp(p->left, p->top + p->height, p->par, TPLIB_BGCOLOR, tplib_systemfont, (UB*)p->ppar);
	return TPLIB_CONTINUE;
}


W	tplib_parts_dec(struct tplib_parts_struct *p, UW cmd)
{
	static	UB	buf[2] = {0, 0};
	W	val, sign, x;
	
	switch (cmd & TPLIB_CMD_MASK) {
		default:
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_REDRAWPART:
			gfil_rec(p->left, p->top, p->left + p->width, p->top + p->height, TPLIB_BGCOLOR);
		case	TPLIB_CMD_REDRAW:
			break;
	}
	
	gdra_stp(p->left, p->top + p->height, TPLIB_CHARCOLOR, TPLIB_BGCOLOR, tplib_systemfont, (UB*)p->config);
	
	if ((p->fn))
		val = p->fn(p, cmd);
	else if ((p->ppar))
		val = *((W*)p->ppar);
	else
		val = p->par;
	
	sign = 0;
	if (val < 0) {
		sign = -1;
		val = -val;
	}
	
	x = p->left + p->width;
	do {
		buf[0] = '0' + (val % 10);
		val /= 10;
		gdra_stp(x -= 8, p->top + p->height, TPLIB_CHARCOLOR, TPLIB_BGCOLOR, tplib_systemfont, buf);
	} while ((val));
	if (sign < 0)
		gdra_stp(x -= 8, p->top + p->height, TPLIB_CHARCOLOR, TPLIB_BGCOLOR, tplib_systemfont, (UB*)"-");
	
	return TPLIB_CONTINUE;
}


W	tplib_parts_button(struct tplib_parts_struct *p, UW cmd)
{
	W	x;
	
	switch (cmd & TPLIB_CMD_MASK) {
		default:
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_REDRAW:
			gfil_rec(p->left, p->top, p->left + p->width, p->top + p->height - 2, TPLIB_PARTSBGCOLOR);
			gfil_rec(p->left, p->top + p->height - 2, p->left + p->width, p->top + p->height, TPLIB_PARTSFGCOLOR);
			x = p->width - gget_stw(tplib_systemfont, (UB*)p->config);
			gdra_stp(p->left + x / 2, p->top + p->height - 4, TPLIB_PARTSCHARCOLOR, TPLIB_PARTSBGCOLOR, tplib_systemfont, (UB*)p->config);
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_PRESS:
			break;
	}
	
	if ((p->fn))
		return p->fn(p, TPLIB_CMD_CHANGE);
	return p->par;
}


W	tplib_parts_buttonhidden(struct tplib_parts_struct *p, UW cmd)
{
	switch (cmd & TPLIB_CMD_MASK) {
		default:
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_PRESS:
			break;
	}
	
	if ((p->fn))
		return p->fn(p, TPLIB_CMD_CHANGE);
	return p->par;
}


W	tplib_parts_buttonalt(struct tplib_parts_struct *p, UW cmd)
{
	W	x, v, ret;
	
	if ((p->ppar))
		v = *((W*)p->ppar);
	else
		v = p->par;
	switch (cmd & TPLIB_CMD_MASK) {
		default:
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_REDRAW:
			gfil_rec(p->left, p->top, p->left + p->width, p->top + p->height - 2, TPLIB_PARTSBGCOLOR);
			gfil_rec(p->left, p->top + p->height - 2, p->left + p->width, p->top + p->height, TPLIB_PARTSFGCOLOR);
			x = p->width - gget_stw(tplib_systemfont, (UB*)p->config);
			gdra_stp(p->left + x / 2, p->top + p->height - 4, TPLIB_PARTSCHARCOLOR, TPLIB_PARTSBGCOLOR, tplib_systemfont, (UB*)p->config);
		case	TPLIB_CMD_REDRAWPART:
			gfil_rec(p->left + 6, p->top + 3, p->left + p->width - 6, p->top + 7, (v)? TPLIB_PARTSONCOLOR : TPLIB_PARTSOFFCOLOR);
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_PRESS:
			break;
	}
	
	v = (v == 0)? 1 : 0;
	if ((p->ppar))
		*((W*)p->ppar) = v;
	else
		p->par = v;
	ret = p->par;
	if ((p->fn)) {
		ret = p->fn(p, TPLIB_CMD_CHANGE);
		if ((p->ppar))
			v = *((W*)p->ppar);
		else
			v = p->par;
	}
	gfil_rec(p->left + 6, p->top + 3, p->left + p->width - 6, p->top + 7, (v)? TPLIB_PARTSONCOLOR : TPLIB_PARTSOFFCOLOR);
	return ret;
}


W	tplib_alwaysselect(struct tplib_parts_struct *p, UW cmd)
{
	W	v;
	
	if (p->ppar == NULL)
		return TPLIB_CONTINUE;
	v = *((W*)p->ppar);
	if (v == p->par)
		return p->par;		/* change to me */
	*((W*)p->ppar) = p->par;
	return TPLIB_CONTINUE;
}


W	tplib_parts_buttongroup(struct tplib_parts_struct *p, UW cmd)
{
	W	x, v, ret;
	
	if (p->ppar == NULL)
		return TPLIB_CONTINUE;
	
	v = *((W*)p->ppar);
	switch (cmd & TPLIB_CMD_MASK) {
		default:
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_REDRAW:
			gfil_rec(p->left, p->top, p->left + p->width, p->top + p->height - 2, TPLIB_PARTSBGCOLOR);
			gfil_rec(p->left, p->top + p->height - 2, p->left + p->width, p->top + p->height, TPLIB_PARTSFGCOLOR);
			x = p->width - gget_stw(tplib_systemfont, (UB*)p->config);
			gdra_stp(p->left + x / 2, p->top + p->height - 4, TPLIB_PARTSCHARCOLOR, TPLIB_PARTSBGCOLOR, tplib_systemfont, (UB*)p->config);
		case	TPLIB_CMD_REDRAWPART:
			gfil_rec(p->left + 6, p->top + 3, p->left + p->width - 6, p->top + 7, (v == p->par)? TPLIB_PARTSONCOLOR : TPLIB_PARTSOFFCOLOR);
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_PRESS:
			break;
	}
	
	if (v != p->par)
		*((W*)p->ppar) = ret = p->par;
	else
		*((W*)p->ppar) = ret = TPLIB_CONTINUE;
#if 0
	ret = p->par;
#endif
	if ((p->fn))
		ret = p->fn(p, TPLIB_CMD_CHANGE);
	v = *((W*)p->ppar);
	tplib_proc(NULL, TPLIB_CMD_REDRAWPART);
	return ret;
}


W	tplib_parts_sliderv(struct tplib_parts_struct *p, UW cmd)
{
	W	v, ret;
	
	switch (cmd & TPLIB_CMD_MASK) {
		default:
			if ((p->ppar))
				v = *((W*)p->ppar);
			else
				v = p->par;
			break;
		case	TPLIB_CMD_PRESS:
		case	TPLIB_CMD_PRESSING:
			v = p->top + p->height - (cmd & 0xfff) - 1;
			break;
	}
	if (v > p->height - 1)
		v = p->height - 1;
	if (v < 0)
		v = 0;
	
	ret = TPLIB_CONTINUE;
	switch (cmd & TPLIB_CMD_MASK) {
		case	TPLIB_CMD_PRESS:
		case	TPLIB_CMD_PRESSING:
			if ((p->ppar))
				*((W*)p->ppar) = v;
			else
				p->par = v;
			ret = p->par;
			
			if ((p->fn)) {
				ret = p->fn(p, TPLIB_CMD_CHANGE);
				if ((p->ppar))
					v = *((W*)p->ppar);
				else
					v = p->par;
				if (v > p->height - 1)
					v = p->height - 1;
				if (v < 0)
					v = 0;
			}
			
		case	TPLIB_CMD_REDRAW:
		case	TPLIB_CMD_REDRAWPART:
			gfil_rec(p->left, p->top, p->left + p->width, p->top + p->height, TPLIB_PARTSBGCOLOR);
			gfil_rec(p->left + p->width / 2 - 1, p->top, p->left + p->width / 2 + 1, p->top + p->height, TPLIB_PARTSFGCOLOR);
			gfil_rec(p->left, p->top + p->height - v - 1, p->left + p->width, p->top + p->height - v, TPLIB_PARTSONCOLOR);
			break;
	}
	
	return ret;
}


W	tplib_proc_redraw(struct tplib_parts_struct *p, UW cmd)
{
	tplib_proc(NULL, TPLIB_CMD_REDRAWPART);		/* draw myself */
	return TPLIB_CONTINUE;
}


W	tplib_parts_log(struct tplib_parts_struct *list, UW cmd)
{
	if ((list)) {
		log_funcname = list->ppar;
		log_fn = list->fn;
		log_sha1 = list->config;
	}
	return TPLIB_CONTINUE;
}


W	tplib_proc(struct tplib_parts_struct *list, UW cmd)
{
	static	W	redraw = 2;
	struct	tplib_parts_struct	*p;
	W	x, y;
	
	x = (cmd >> 12) & 0xfff;
	y = cmd & 0xfff;
	
	switch (cmd & TPLIB_CMD_MASK) {
		case	TPLIB_CMD_REDRAW:
			redraw |= 2;
			return TPLIB_CONTINUE;
		case	TPLIB_CMD_REDRAWPART:
			redraw |= 1;
			return TPLIB_CONTINUE;
	}
	if (list == NULL)
		return TPLIB_CONTINUE;
	{
		W	l, t, w, h;
		
		l = t = w = h = 0;
		p = list;
		while ((p->parts)) {
			if ((p->left & TPLIB_REL))
				p->left = l + (p->left - TPLIB_REL);
			l = p->left;
			if ((p->top & TPLIB_REL))
				p->top = t + (p->top - TPLIB_REL);
			t = p->top;
			if ((p->width & TPLIB_REL))
				p->width = w + (p->width - TPLIB_REL);
			w = p->width;
			if ((p->height & TPLIB_REL))
				p->height = h + (p->height - TPLIB_REL);
			h = p->height;
			l += w;
			p++;
		}
	}
	if ((redraw)) {
		p = list;
		while ((p->parts)) {
			p->parts(p, (redraw & 2)? TPLIB_CMD_REDRAW : TPLIB_CMD_REDRAWPART);
			p++;
		}
		redraw = 0;
	}
	log_funcname = NULL;
	log_fn = NULL;
	log_sha1 = NULL;
	switch (cmd & TPLIB_CMD_MASK) {
		case	TPLIB_CMD_PRESS:
		case	TPLIB_CMD_PRESSING:
			p = list;
			while ((p->parts)) {
				if (x < p->left)
					;
				else if (x >= p->left + p->width)
					;
				else if (y < p->top)
					;
				else if (y >= p->top + p->height)
					;
				else {
					W	ret;
					
					if (((cmd & TPLIB_CMD_MASK) == TPLIB_CMD_PRESS)&&(log_funcname)) {
						lcdtp_sendlogs("#PRESS:");
						if ((log_sha1))
							lcdtp_sendlogs(log_sha1);
						lcdtp_sendlogc(':');
						lcdtp_sendlogs(log_funcname);
						lcdtp_sendlogc('[');
						lcdtp_sendlogdec(p - list);
						lcdtp_sendlogc(']');
						if ((p->config))
							lcdtp_sendlogs(p->config);
						lcdtp_sendlogs("\n");
						ret = p->parts(p, cmd);
						lcdtp_sendlogs("#RET:");
						lcdtp_sendloguw(ret);
						lcdtp_sendlogs("\n");
						if ((log_fn))
							log_fn(p, cmd);
						if (ret != TPLIB_CONTINUE)
							return ret;
					} else {
						if ((ret = p->parts(p, cmd)) != TPLIB_CONTINUE)
							return ret;
					}
				}
				p++;
			}
			break;
	}
	return TPLIB_CONTINUE;
}


W	tplib_config2ppar(struct tplib_parts_struct *p, UW cmd)
{
	void	**q, *r;
	
	if ((q = p->config) == NULL)
		p->ppar = NULL;
	else if ((r = *q) == NULL)
		p->ppar = NULL;
	else
		p->ppar = r;
	return TPLIB_CONTINUE;
}


W	tplib_setupflip(void *message)
{
#ifdef	LCDTP_FLIP_X
	static	UB	*s;
	static	struct	tplib_parts_struct	parts[] = {
		{tplib_parts_fill, 0, 0, LCD_W, LCD_H, 0x0000, NULL, NULL, NULL, 0}, 
		{tplib_parts_buttonhidden, LCD_W / 16, LCD_H / 8, LCD_W * 3 / 8, LCD_H / 4, LCDTP_FLIP_X | LCDTP_FLIP_Y, NULL, NULL, NULL, 0}, 
		{tplib_parts_buttonhidden, LCD_W * 9 / 16, LCD_H / 8, LCD_W * 3 / 8, LCD_H / 4, LCDTP_FLIP_Y, NULL, NULL, NULL, 0}, 
		{tplib_parts_buttonhidden, LCD_W / 16, LCD_H * 5 / 8, LCD_W * 3 / 8, LCD_H / 4, LCDTP_FLIP_X, NULL, NULL, NULL, 0}, 
		{tplib_parts_button, LCD_W * 9 / 16, LCD_H * 5 / 8, LCD_W * 3 / 8, LCD_H / 4, 0, NULL, NULL, "->", 0}, 
		{tplib_parts_text, LCD_W / 8, LCD_H * 3 / 8, LCD_W * 3 / 4, 24, TPLIB_CHARCOLOR, NULL, tplib_config2ppar, &s, 0}, 
		{NULL}
	};
	s = message;
	
	tplib_proc(NULL, TPLIB_CMD_REDRAW);
	while ((lcdtp_flip = tplib_proc(parts, gettp())) == TPLIB_CONTINUE)
		;
	
	tplib_proc(NULL, TPLIB_CMD_REDRAW);
#endif
	return TPLIB_CONTINUE;
}


W	tplib_proc_tenkey(struct tplib_parts_struct *p, UW cmd)
{
	static	W	val;
	static	struct	tplib_parts_struct	parts[] = {
		{tplib_parts_fill, 0, 0, LCD_W, LCD_H, 0x0000, NULL, NULL, NULL, 0}, 
		{tplib_parts_dec, 16, 16, 112, 24, 0, &val, NULL, NULL, 0}, 
		{tplib_parts_button, TPLIB_REL + 32, TPLIB_REL, 64, 32, -1, NULL, NULL, "<-", 0}, 
		{tplib_parts_button, 16, TPLIB_REL + 48, 64, 48, 7, NULL, NULL, "7", 0}, 
		{tplib_parts_button, TPLIB_REL + 8, TPLIB_REL, 64, 48, 8, NULL, NULL, "8", 0}, 
		{tplib_parts_button, TPLIB_REL + 8, TPLIB_REL, 64, 48, 9, NULL, NULL, "9", 0}, 
		{tplib_parts_button, 16, TPLIB_REL + 64, 64, 48, 4, NULL, NULL, "4", 0}, 
		{tplib_parts_button, TPLIB_REL + 8, TPLIB_REL, 64, 48, 5, NULL, NULL, "5", 0}, 
		{tplib_parts_button, TPLIB_REL + 8, TPLIB_REL, 64, 48, 6, NULL, NULL, "6", 0}, 
		{tplib_parts_button, 16, TPLIB_REL + 64, 64, 48, 1, NULL, NULL, "1", 0}, 
		{tplib_parts_button, TPLIB_REL + 8, TPLIB_REL, 64, 48, 2, NULL, NULL, "2", 0}, 
		{tplib_parts_button, TPLIB_REL + 8, TPLIB_REL, 64, 48, 3, NULL, NULL, "3", 0}, 
		{tplib_parts_button, 16, 256 + 16, 64, 32, -2, NULL, NULL, "cancel", 0}, 
		{tplib_parts_button, TPLIB_REL + 8, 256, 64, 48, 0, NULL, NULL, "0", 0}, 
		{tplib_parts_button, TPLIB_REL + 8, 256 + 16, 64, 32, -3, NULL, NULL, "OK", 0}, 
		{NULL}
	};
	
	if (p == NULL)
		val = 0;
	else if ((p->ppar))
		val = *((W*)p->ppar);
	else
		val = p->par;
	
	tplib_proc(NULL, TPLIB_CMD_REDRAW);		/* draw myself */
	
	for (;;) {
		W	ret;
		
		switch (ret = tplib_proc(parts, gettp())) {
			case	TPLIB_CONTINUE:
				continue;
			default:
				if (val > 99999999)
					continue;
				val = val * 10 + ret;
				tplib_proc(NULL, TPLIB_CMD_REDRAWPART);		/* draw myself */
				continue;
			case	-1:		/* <- */
				val /= 10;
				tplib_proc(NULL, TPLIB_CMD_REDRAWPART);		/* draw myself */
				continue;
			case	-2:		/* cancel */
				tplib_proc(NULL, TPLIB_CMD_REDRAW);		/* draw parent screen */
				return TPLIB_CONTINUE;
			case	-3:		/* ok */
				tplib_proc(NULL, TPLIB_CMD_REDRAW);		/* draw parent screen */
				if (p == NULL)
					return val;
				if ((p->ppar))
					*((W*)p->ppar) = val;
				else
					p->par = val;
				return p->par;
		}
	}
}


