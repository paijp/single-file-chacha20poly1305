#!/bin/sh
#
# fifo-drain.sh <fifo> [max-bytes] — used by index.php; not usually run by hand.
#
# Print up to max-bytes (default 1000; index.php passes the reply budget
# derived from the device's "s" parameter) from the FIFO to stdout without
# blocking, then keep
# the pipe's contents alive for the next request by parking a detached
# holder (`sleep 10`) on it. FIFO data survives only while some fd is open,
# and the web request that read it is about to exit — the holder bridges
# the gap to the next request.
#
# The holder's stdout/stderr go to /dev/null so PHP's shell_exec() sees EOF
# (and returns) the moment this script exits; it does not wait the 10 s.
# Writers that arrive after the holder dies simply block in open() until
# the next request re-opens the FIFO, so nothing is lost across idle gaps —
# only bytes left unread through 10+ s of no requests are dropped.

fifo="$1"
max="${2:-1000}"
exec 3<>"$fifo"
[ "$max" -gt 0 ] 2>/dev/null || max=0
if [ "$max" -gt 0 ]; then
	dd if="$fifo" iflag=nonblock bs="$max" count=1 2>/dev/null
fi
sleep 10 <&3 >/dev/null 2>&1 &
exec 3>&-
