#!/bin/sh

PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin"
DIR="/etc/openvpn"

ALLOW=0
DENY=1

# check if cert is on the crl
grep -q "^$2\$" $DIR/certs.deny && echo `date "+%Y%m%d-%H:%M:%S"` " denied" "$2" >> $DIR/log.deny && exit $DENY

## check if cert is in the allowed list and exit positive
#grep -q "^$2\$" $DIR/certs.allow && echo `date "+%Y%m%d-%H:%M:%S"` " allowed" "$2" >> $DIR/log.allow && exit $ALLOW
#
## fail to safe
#echo `date "+%Y%m%d-%H:%M:%S"` " unknown" "$2" >> $DIR/log.deny
#exit $DENY

# dont bother checking the allowed list, assume no deny is cool
# we can unhash the above when we have a mech for adding certs to
# the allow list automagically on creation
exit $ALLOW

