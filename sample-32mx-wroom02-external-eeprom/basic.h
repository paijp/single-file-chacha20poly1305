
#ifndef	NULL
#define	NULL	((void*)0)
#endif

typedef signed	char	 B;
typedef signed	short	 H;
#ifdef	__unix__
typedef signed	int	 W;
#else
typedef signed	long	 W;
#endif
typedef unsigned char	UB;
typedef unsigned short	UH;
#ifdef	__unix__
typedef unsigned int	UW;
#else
typedef unsigned long	UW;
#endif

typedef	volatile B	_B;
typedef	volatile H	_H;
typedef	volatile W	_W;
typedef	volatile UB	_UB;
typedef	volatile UH	_UH;
typedef	volatile UW	_UW;


