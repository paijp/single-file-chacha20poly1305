#!/bin/sh
#
# to-drain.sh <fifo> — used by index.php; not usually run by hand.
#
# Print up to 200 bytes from the FIFO to stdout without blocking, then keep
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
exec 3<>"$fifo"
dd if="$fifo" iflag=nonblock bs=200 count=1 2>/dev/null
sleep 10 <&3 >/dev/null 2>&1 &
exec 3>&-
