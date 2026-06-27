DEVICE	= 32MX270F256B
XC32	= /opt/microchip/xc32/v1.42/bin

SECRETS	= $(if $(WIFI_SSID),'-DWIFI_SSID="$(WIFI_SSID)"') \
	  $(if $(WIFI_PASS),'-DWIFI_PASS="$(WIFI_PASS)"') \
	  $(if $(WIFI_HOST),'-DWIFI_HOST="$(WIFI_HOST)"')

help:
	@awk '/#[#]/{sub(":[^#]*", "\t\t");print $$0;}' makefile

%.hex:	%.c
	$(XC32)/xc32-gcc -mprocessor=$(DEVICE) -ffreestanding -fno-hosted -nodefaultlibs -membedded-data -Wall -Wno-pointer-sign -O1 -I . $(SECRETS) -c $<
	$(XC32)/xc32-gcc -mprocessor=$(DEVICE) -mno-float -Wl,-Map=$*.map -o $*.out $*.o
	$(XC32)/xc32-bin2hex $*.out
