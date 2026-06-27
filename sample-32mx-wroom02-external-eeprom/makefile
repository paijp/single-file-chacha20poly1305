DEVICE	= 32MX270F256B
XC32	= /opt/microchip/xc32/v1.42/bin

SECRETS	= $(if $(WIFI_SSID),-DWIFI_SSID=$(WIFI_SSID)) \
	  $(if $(WIFI_PASS),-DWIFI_PASS=$(WIFI_PASS)) \
	  $(if $(WIFI_HOST),-DWIFI_HOST=$(WIFI_HOST))

CFLAGS	= -mprocessor=$(DEVICE) -ffreestanding -fno-hosted -nodefaultlibs -membedded-data -Wall -Wno-pointer-sign -O1 -I .
LDFLAGS	= -mprocessor=$(DEVICE) -mno-float

LIBOBJS	= lcdtp.o tplib.o

help:
	@awk '/#[#]/{sub(":[^#]*", "\t\t");print $$0;}' makefile

%.o:	%.c
	$(XC32)/xc32-gcc $(CFLAGS) $(SECRETS) -c $<

wroomc20p1305.hex:	wroomc20p1305.o $(LIBOBJS)
	$(XC32)/xc32-gcc $(LDFLAGS) -Wl,-Map=wroomc20p1305.map -o wroomc20p1305.out $^
	$(XC32)/xc32-bin2hex wroomc20p1305.out
