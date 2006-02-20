#!/usr/bin/perl
use strict;
use Data::Dumper;
use Test::More tests => 68;

my ($text, $obj);

BEGIN { use_ok ( 'Funknet::Whois::Object' ); }

# Parsing objects without timestamp: attribute.

# 1: aut-num
$text = <<'TEXT';

aut-num:      AS65001
as-name:      MUNKY-NODNOL-ORG
descr:        munky.nodnol.org
import:       from AS65000 action pref=100; accept AS-FUNKTRANSIT and not AS65001
import:       from AS65023 action pref=100; accept AS-FUNKTRANSIT and not AS65001
export:       to AS65000 announce AS65001
export:       to AS65023 announce AS65001
tun:          SPLURBY-MUNKY
tun:          BLANK-MUNKY
admin-c:      CA1-FUNKNET
tech-c:       CA1-FUNKNET
mnt-by:       CHRIS
notify:       chris@nodnol.org
changed:      chris@nodnol.org 20040321
source:       FUNKNET

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                'parse ok' );
is( _nw(scalar $obj->text),        _nw($text),   'text correct');
is( ref $obj,          'Funknet::Whois::Object', 'correct class' );
is( $obj->object_type, 'aut-num',                'correct type' );
is( $obj->object_name, 'AS65001',                'correct name' );
is( $obj->source,      'FUNKNET',                'source ok' );

my @array = $obj->ximport; 
is( scalar @array,  2,                  'multiple import lines via ximport' );
@array = $obj->export; 
is( scalar @array,  2,                  'multiple export lines' );

# 2: key-cert

$text = <<'TEXT';

key-cert:     PGPKEY-B355A313
method:       PGP
owner:        Chris Andrews (Standard Key) <chris@nodnol.org>
fingerpr:     06B7 F9D1 4098 E3CA E145  C0DB 45A1 E890 B355 A313
source:       FUNKNET
certif:       -----BEGIN PGP PUBLIC KEY BLOCK-----
certif:       Version: GnuPG v1.0.7 (SunOS)
certif:
certif:       mQGiBD1FPckRBADGBFSY39qpevb3dmmHuW5gSfSF7T6ZgZu3TsM5+gE1B8zLX4Lw
certif:       Sq3NDvKfbUNCLnG1wgtbwdOsI0Zigv2JcuOzSoMZ9wj1zW1w0oGH6xJmgvZem+F6
certif:       /VPcSDvS7NVjp52oa8kUysubnxmdVjKqytNV2PYlHhk11qsw8viwJ7QrhwCgg/Kh
certif:       fv+gfPzOfxBDKCWBGB23h5sD/30XwmvOTVHyy3O6d0OYt/BdWS22mSPxNprrY0wM
certif:       6aZ3B6dhH2gU1V+Rt1qpcuWtzDQjlTP2VzChXxjiPM52eNs+EKZDhE4MDiwc/KE8
certif:       Lilui5ifgrz9K2zXEUHhle1IclS0MCC2DXkEsTk1wCbh7bMjiFe2vWGvK91iqTYl
certif:       yir2A/4+/HtNdoikhxG1gUF3ZN5T3JAzHSx0RyRDIc2wb1NK41cMboz6dvqxFWni
certif:       3WL8Zppwdk0qwpUgAOIzTq+oqfE8e6lucpkVVpeZ9GNiPRRCLeH00JD3NkOivzxr
certif:       IHkmvzhBg6YlhL5UT+ocxKNlrJsY9HQVhC9y4txhGVF4Vh8AIrQvQ2hyaXMgQW5k
certif:       cmV3cyAoU3RhbmRhcmQgS2V5KSA8Y2hyaXNAbm9kbm9sLm9yZz6IWQQTEQIAGQUC
certif:       PUU9yQQLBwMCAxUCAwMWAgECHgECF4AACgkQRaHokLNVoxOikgCfXWe95TgyQUNX
certif:       cotZ97ZrLZJADUMAn1yFBXlMm4ws42qImTk1EQB8mgWXiEYEExECAAYFAj5iU5EA
certif:       CgkQiGjP99nB6xH//ACgiVFxXmwok0oBr3fDHMPAcJNLpaIAn2BKHo4fWIdybowC
certif:       YTIfIMoFh1OuiEYEExECAAYFAj5iVBIACgkQC1xl8OWtguCfXACgv9Z4wKYSmIXg
certif:       ETF8540NSSd83GgAn060xCOHdFN4wFcWLiwnBsuiUXENuQENBD1FPlQQBAC+nIFI
certif:       hG4eBAJuMHcyRts3NLLfSWiCZjFWTc5OhQIrz53GKnkkRFwDh5Dp84wAXv9cmqrs
certif:       OX+VugO4WWMtMFfr2f0XGcCMLZBdaYzz+wyKHVQLuCf7SthweMmqaCeznYtOwbSf
certif:       acjagLB7IlOrS2oPm6zs+K7KVNiwxuByTAyfZwAEDQP/c2qu7Yhnpxyuyj8NYv7e
certif:       QxTP1fUytJUrQO89hLLF+BapkROmE8c7gq4W1pYMBL3OCpLRIGzoQUK34do4rhwi
certif:       0d4YpJNuWsxQr75eoIpY/NVKm1rqJ1l8yMl8Rg/3tNvtPcwdsFF1nJWIQKitWxZZ
certif:       glmliw6RIv9rA5pZPOeyLa2IRQQYEQIABgUCPUU+VAAKCRBFoeiQs1WjEz+9AJ48
certif:       dKfDmM3fm4yYRr8nDYCaLBlO3gCY5WoFkwVKmMBxJt3NH4C//xffVw==
certif:       =JHMM
certif:       -----END PGP PUBLIC KEY BLOCK-----
mnt-by:       CHRIS
changed:      chris@nodnol.org 20030305

TEXT

my $rawtext = <<'TEXT';
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.0.7 (SunOS)

mQGiBD1FPckRBADGBFSY39qpevb3dmmHuW5gSfSF7T6ZgZu3TsM5+gE1B8zLX4Lw
Sq3NDvKfbUNCLnG1wgtbwdOsI0Zigv2JcuOzSoMZ9wj1zW1w0oGH6xJmgvZem+F6
/VPcSDvS7NVjp52oa8kUysubnxmdVjKqytNV2PYlHhk11qsw8viwJ7QrhwCgg/Kh
fv+gfPzOfxBDKCWBGB23h5sD/30XwmvOTVHyy3O6d0OYt/BdWS22mSPxNprrY0wM
6aZ3B6dhH2gU1V+Rt1qpcuWtzDQjlTP2VzChXxjiPM52eNs+EKZDhE4MDiwc/KE8
Lilui5ifgrz9K2zXEUHhle1IclS0MCC2DXkEsTk1wCbh7bMjiFe2vWGvK91iqTYl
yir2A/4+/HtNdoikhxG1gUF3ZN5T3JAzHSx0RyRDIc2wb1NK41cMboz6dvqxFWni
3WL8Zppwdk0qwpUgAOIzTq+oqfE8e6lucpkVVpeZ9GNiPRRCLeH00JD3NkOivzxr
IHkmvzhBg6YlhL5UT+ocxKNlrJsY9HQVhC9y4txhGVF4Vh8AIrQvQ2hyaXMgQW5k
cmV3cyAoU3RhbmRhcmQgS2V5KSA8Y2hyaXNAbm9kbm9sLm9yZz6IWQQTEQIAGQUC
PUU9yQQLBwMCAxUCAwMWAgECHgECF4AACgkQRaHokLNVoxOikgCfXWe95TgyQUNX
cotZ97ZrLZJADUMAn1yFBXlMm4ws42qImTk1EQB8mgWXiEYEExECAAYFAj5iU5EA
CgkQiGjP99nB6xH//ACgiVFxXmwok0oBr3fDHMPAcJNLpaIAn2BKHo4fWIdybowC
YTIfIMoFh1OuiEYEExECAAYFAj5iVBIACgkQC1xl8OWtguCfXACgv9Z4wKYSmIXg
ETF8540NSSd83GgAn060xCOHdFN4wFcWLiwnBsuiUXENuQENBD1FPlQQBAC+nIFI
hG4eBAJuMHcyRts3NLLfSWiCZjFWTc5OhQIrz53GKnkkRFwDh5Dp84wAXv9cmqrs
OX+VugO4WWMtMFfr2f0XGcCMLZBdaYzz+wyKHVQLuCf7SthweMmqaCeznYtOwbSf
acjagLB7IlOrS2oPm6zs+K7KVNiwxuByTAyfZwAEDQP/c2qu7Yhnpxyuyj8NYv7e
QxTP1fUytJUrQO89hLLF+BapkROmE8c7gq4W1pYMBL3OCpLRIGzoQUK34do4rhwi
0d4YpJNuWsxQr75eoIpY/NVKm1rqJ1l8yMl8Rg/3tNvtPcwdsFF1nJWIQKitWxZZ
glmliw6RIv9rA5pZPOeyLa2IRQQYEQIABgUCPUU+VAAKCRBFoeiQs1WjEz+9AJ48
dKfDmM3fm4yYRr8nDYCaLBlO3gCY5WoFkwVKmMBxJt3NH4C//xffVw==
=JHMM
-----END PGP PUBLIC KEY BLOCK-----
TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                'parse ok' );
is( _nw(scalar $obj->text),        _nw($text),   'text correct');
is( ref $obj,          'Funknet::Whois::Object', 'correct class' );
is( $obj->object_type, 'key-cert',               'correct type' );
is( $obj->object_name, 'PGPKEY-B355A313',        'correct name' );
is( $obj->source,      'FUNKNET',                'source ok' );

my $obj_rawtext = $obj->rawtext();
is( $obj_rawtext,      $rawtext,                 'rawtext ok' );

# Parsing objects with timestamps.

# 1: aut-num with correct timestamp

$text = <<'TEXT';

aut-num:      AS65001
as-name:      MUNKY-NODNOL-ORG
descr:        munky.nodnol.org
import:       from AS65000 action pref=100; accept AS-FUNKTRANSIT and not AS65001
import:       from AS65023 action pref=100; accept AS-FUNKTRANSIT and not AS65001
export:       to AS65000 announce AS65001
export:       to AS65023 announce AS65001
tun:          SPLURBY-MUNKY
tun:          BLANK-MUNKY
admin-c:      CA1-FUNKNET
tech-c:       CA1-FUNKNET
mnt-by:       CHRIS
notify:       chris@nodnol.org
changed:      chris@nodnol.org 20040321
timestamp:    2005-10-01T14:49:00
source:       FUNKNET

TEXT

$obj = Funknet::Whois::Object->new($text, TimeStamp => 1);

ok( defined $obj,                                'parse ok' );
is( _nw(scalar $obj->text),        _nw($text),   'text correct');
is( ref $obj,          'Funknet::Whois::Object', 'correct class' );
is( $obj->object_type, 'aut-num',                'correct type' );
is( $obj->object_name, 'AS65001',                'correct name' );
is( $obj->source,      'FUNKNET',                'source ok' );
is( $obj->epoch_time,  1128178140,               'epoch time correct' );

# 1: aut-num with invalid timestamp

$text = <<'TEXT';

aut-num:      AS65001
as-name:      MUNKY-NODNOL-ORG
descr:        munky.nodnol.org
import:       from AS65000 action pref=100; accept AS-FUNKTRANSIT and not AS65001
import:       from AS65023 action pref=100; accept AS-FUNKTRANSIT and not AS65001
export:       to AS65000 announce AS65001
export:       to AS65023 announce AS65001
tun:          SPLURBY-MUNKY
tun:          BLANK-MUNKY
admin-c:      CA1-FUNKNET
tech-c:       CA1-FUNKNET
mnt-by:       CHRIS
notify:       chris@nodnol.org
changed:      chris@nodnol.org 20040321
timestamp:    2005aaaa-10-01T14:49:00
source:       FUNKNET

TEXT

$obj = Funknet::Whois::Object->new($text, TimeStamp => 1);

ok( !defined $obj, 'failed parse ok' );

# parsing objects with continuation lines

$text = <<'TEXT';

aut-num:      AS65001
as-name:      MUNKY-NODNOL-ORG
descr:        munky.nodnol.org
import:       from AS65000 action pref=100; 
 accept AS-FUNKTRANSIT and not AS65001
import:       
+ from AS65023 action pref=100; 
+ accept AS-FUNKTRANSIT and not AS65001
export:       to AS65000 announce AS65001
export:       to AS65023 announce AS65001
tun:          SPLURBY-MUNKY
tun:          BLANK-MUNKY
admin-c:      CA1-FUNKNET
tech-c:       CA1-FUNKNET
mnt-by:       CHRIS
notify:       chris@nodnol.org
changed:      chris@nodnol.org 20040321
timestamp:    2005-10-01T14:49:00
source:       FUNKNET

TEXT

my $parsed_text = <<'PARSED';
aut-num: AS65001
as-name: MUNKY-NODNOL-ORG
descr: munky.nodnol.org
import: from AS65000 action pref=100;  accept AS-FUNKTRANSIT and not AS65001
import: from AS65023 action pref=100;  accept AS-FUNKTRANSIT and not AS65001
export: to AS65000 announce AS65001
export: to AS65023 announce AS65001
tun: SPLURBY-MUNKY
tun: BLANK-MUNKY
admin-c: CA1-FUNKNET
tech-c: CA1-FUNKNET
mnt-by: CHRIS
notify: chris@nodnol.org
changed: chris@nodnol.org 20040321
timestamp: 2005-10-01T14:49:00
source: FUNKNET
PARSED

$obj = Funknet::Whois::Object->new($text, TimeStamp => 1);

ok( defined $obj,                                'parse ok' );
is( _nw(scalar $obj->text), _nw($parsed_text),   'parsed text correct');
is( ref $obj,          'Funknet::Whois::Object', 'correct class' );
is( $obj->object_type, 'aut-num',                'correct type' );
is( $obj->object_name, 'AS65001',                'correct name' );
is( $obj->source,      'FUNKNET',                'source ok' );

@array = $obj->ximport; 
is( scalar @array,  2,                  'multiple import lines via ximport' );
is( $array[0],      'from AS65000 action pref=100;  accept AS-FUNKTRANSIT and not AS65001', 'import line 1 ok' );
is( $array[1],      ' from AS65023 action pref=100;  accept AS-FUNKTRANSIT and not AS65001', 'import line 2 ok' );

# parsing an object that doesn't exist

$text = <<'TEXT';

fictional:   attribute
another:     fictional
attribute:   here

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                    'parse ok');
is( _nw(scalar $obj->text),    _nw($text),           'text correct');
is( $obj->error(), 'Unknown object type: fictional', 'fictional object detected');

# single missing mandatory key

$text = <<'TEXT';

route:        192.168.101.0/24
descr:        MUNKYII-XEN
origin:       AS65001
mnt-by:       CHRIS
changed:      chris@nodnol.org 20040321

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                         'parse ok');
is( _nw(scalar $obj->text),    _nw($text),                'text correct');
is( $obj->error(), 'Missing mandatory attribute: source', 'missing attribute detected');

# multiple missing mandatory key

$text = <<'TEXT';

route:        192.168.101.0/24
descr:        MUNKYII-XEN
origin:       AS65001
changed:      chris@nodnol.org 20040321

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                                  'parse ok');
is( _nw(scalar $obj->text),    _nw($text),                         'text correct');
is( $obj->error(), 'Missing mandatory attributes: mnt-by, source', 'missing attributes detected');

# one 'single'-defined attribute used more than once

$text = <<'TEXT';

route:        192.168.101.0/24
descr:        MUNKYII-XEN
origin:       AS65001
mnt-by:       CHRIS
changed:      chris@nodnol.org 20040321
source:       FUNKNET
source:       NOTFUNKNET

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                                 'parse ok');
is( _nw(scalar $obj->text),    _nw($text),                        'text correct');
is( $obj->error(), 'Unique attribute source used multiple times', 'unique attribute used >1 detected');

# multiple 'single'-defined attributes used more than once

$text = <<'TEXT';

route:        192.168.101.0/24
descr:        MUNKYII-XEN
origin:       AS65001
origin:       AS65002
mnt-by:       CHRIS
changed:      chris@nodnol.org 20040321
source:       FUNKNET
source:       NOTFUNKNET

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                                          'parse ok');
is( _nw(scalar $obj->text),    _nw($text),                                 'text correct');
is( $obj->error(), 'Unique attributes origin, source used multiple times', 'multiple unique attributes used >1 detected');

# one unknown attribute

$text = <<'TEXT';

route:        192.168.101.0/24
descr:        MUNKYII-XEN
origin:       AS65001
mnt-by:       CHRIS
changed:      chris@nodnol.org 20040321
source:       FUNKNET
jibjib:       woo

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                              'parse ok');
is( _nw(scalar $obj->text),    _nw($text),     'text correct');
is( $obj->error(), 'Unknown attribute jibjib', 'unknown attribute detected');

# multiple unknown attributes

$text = <<'TEXT';

route:        192.168.101.0/24
descr:        MUNKYII-XEN
origin:       AS65001
mnt-by:       CHRIS
changed:      chris@nodnol.org 20040321
source:       FUNKNET
jibjib:       woo
woo:          jibjib

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                    'parse ok');
is( _nw(scalar $obj->text),    _nw($text),           'text correct');
is( $obj->error(), 'Unknown attributes jibjib, woo', 'multiple unknown attributes detected');

# combination

$text = <<'TEXT';

route:        192.168.101.0/24
descr:        MUNKYII-XEN
mnt-by:       CHRIS
changed:      chris@nodnol.org 20040321
jibjib:       woo
source:       FUNKNET
source:       NOTFUNKNET
woo:          jibjib

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj, 'parse ok');
is( _nw(scalar $obj->text), _nw($text), 'text correct');
is( $obj->error(), 
    "Missing mandatory attribute: origin\n" . 
    "Unique attribute source used multiple times\n" .
    "Unknown attributes jibjib, woo", 'multiple problems detected');

# regexing

$text = <<'TEXT';

route:        192.168.101.0/24/16
descr:        MUNKYII-XEN
mnt-by:       CHRIS
origin:       AS65001
changed:      chris@nodnol.org 20040321
source:       FUNKNET

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                                                   'parse ok');
is( _nw(scalar $obj->text), _nw($text),                                             'text correct');
is( $obj->error(), 'Invalid value \'192.168.101.0/24/16\' for attribute \'route\'', 'bad prefix detected');

$text = <<'TEXT';

route:        192.168.101.0/24/16
descr:        MUNKYII-XEN
mnt-by:       CHRIS
origin:       AS650014242424
changed:      chris@nodnol.org 20040321
source:       FUNKNET

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj, 'parse ok');
is( _nw(scalar $obj->text), _nw($text), 'text correct');
is( $obj->error(), 
    "Invalid values 'AS650014242424' for attribute 'origin', " .
                   "'192.168.101.0/24/16' for attribute 'route'",
    'multiple bad values detected');

$text = <<'TEXT';

aut-num:      AS65027
as-name:      COLON
descr:        colon.colondot.net own AS, to facilitate later routing to home
descr:        NO giving me non-RFC1918. :-P
remarks:      ==================================
remarks:      Central Nodes (transit routes)
remarks:      ----------------------------------
remarks:      SPLURBY (AS65000)
import:       from AS65000 action pref=100; accept AS-FUNKTRANSIT AND NOT AS-SEMICOLONDOT AND {10.0.0.0/8^+ , 172.16.0.0/12^+ , 192.168.0.0/16^+}
export:       to AS65000 announce AS-SEMICOLONDOT
remarks:      ----------------------------------
remarks:      BLANK (AS65023)
import:       from AS65023 action pref=100; accept AS-FUNKTRANSIT AND NOT AS-SEMICOLONDOT AND {10.0.0.0/8^+ , 172.16.0.0/12^+ , 192.168.0.0/16^+}
export:       to AS65023 announce AS-SEMICOLONDOT
remarks:      ----------------------------------
remarks:      MUNKYII (AS65030)
import:       from AS65030 action pref=100; accept AS-FUNKTRANSIT AND NOT AS-SEMICOLONDOT AND {10.0.0.0/8^+ , 172.16.0.0/12^+ , 192.168.0.0/16^+}
export:       to AS65030 announce AS-SEMICOLONDOT
remarks:      ==================================
tun:          COLON-SPLURBY
tun:          COLON-BLANK
tun:          COLON-MUNKYII
admin-c:      MB1-FUNKNET
tech-c:       MB1-FUNKNET
mnt-by:       MBM-MNT
notify:       mbm+funknet@colondot.net
changed:      mbm@colondot.net 20040222
changed:      mbm@colondot.net 20040707
changed:      mbm@colondot.net 20040707
source:       FUNKNET

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj, 'parse ok');
is( _nw(scalar $obj->text), _nw($text), 'text correct');

$text = <<'TEXT';

aut-num:      AS65027
as-name:      COLON
descr:        colon.colondot.net own AS, to facilitate later routing to home
descr:        NO giving me non-RFC1918. :-P
import:       from AS65000 action pref=100; accept AS-FUNKTRANSIT AND NOT AS-SEMICOLONDOT AND {10.0.0.0/8^+ , 172.16.0.0/12^+ , 192.168.0.0/16^+}
export:       to AS65000 announce AS-SEMICOLONDOT
import:       from AS65023 action pref=100; accept AS-FUNKTRANSIT AND NOT AS-SEMICOLONDOT AND {10.0.0.0/8^+ , 172.16.0.0/12^+ , 192.168.0.0/16^+}
export:       to AS65023 announce AS-SEMICOLONDOT
import:       from AS65030 action pref=100; accept AS-FUNKTRANSIT AND NOT AS-SEMICOLONDOT AND {10.0.0.0/8^+ , 172.16.0.0/12^+ , 192.168.0.0/16^+}
export:       to AS65030 announce AS-SEMICOLONDOT
tun:          COLON-SPLURBY
tun:          COLON-BLANK
tun:          COLON-MUNKYII
admin-c:      MB1-FUNKNET
tech-c:       MB1-FUNKNET
mnt-by:       MBM-MNT
notify:       mbm+funknet@colondot.net
changed:      mbm@colondot.net 20040222
changed:      mbm@colondot.net 20040707
changed:      mbm@colondot.net 20040707
source:       FUNKNET

TEXT

$obj = Funknet::Whois::Object->new($text);

ok( defined $obj, 'parse ok');
is( _nw(scalar $obj->text), _nw($text), 'text correct');


my $rawcert = <<'RAWCERT';
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 5 (0x5)
        Signature Algorithm: md5WithRSAEncryption
        Issuer: C=GB, ST=FunkSTate, L=FunkLocality, O=FUNKNET, OU=FunkOU, CN=FUNKNET/emailAddress=ca@funknet.org
        Validity
            Not Before: Jan 29 02:39:32 2006 GMT
            Not After : Jan 29 02:39:32 2007 GMT
        Subject: C=GB, ST=FunkSTate, L=FunkLocality, O=FUNKNET, OU=FunkOU, CN=BLANKserver/emailAddress=blankserver@funknet.org
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:d2:9f:ed:62:5f:07:60:71:bd:32:8b:28:d7:2c:
                    bd:b5:46:c9:1d:8b:91:91:81:43:fd:21:11:03:a2:
                    93:28:08:13:e2:d5:4c:15:2a:a5:20:9d:53:ef:c2:
                    4e:19:f8:90:3c:00:48:7e:ba:10:4c:9f:bd:2d:9c:
                    d7:04:a3:dd:fd:d7:3e:61:7f:9c:b3:d6:37:63:91:
                    41:e9:5e:41:e3:1e:fc:15:48:2e:60:5d:ea:d9:99:
                    d2:6c:1b:82:19:93:90:1e:d6:b8:80:98:b4:bd:69:
                    99:4f:28:45:0b:33:89:ca:40:50:37:1e:fa:20:92:
                    7c:ff:ca:99:2f:9c:fc:5b:9f:d9:a4:c3:eb:e5:21:
                    d0:06:68:02:84:b4:60:25:57:64:bc:5c:42:75:9b:
                    17:07:5c:93:cd:65:10:70:af:77:56:72:42:79:04:
                    26:30:ef:4c:f6:6c:c8:a9:4d:2a:88:10:ac:82:d4:
                    a3:c0:87:78:4f:51:ae:f7:eb:4c:5c:b9:8c:c0:be:
                    1e:8e:b3:f2:40:04:d4:e6:d4:94:7a:28:55:a1:f3:
                    11:21:8d:21:cc:00:eb:f5:94:bb:ac:09:1f:48:f9:
                    02:c5:51:5d:f7:ea:11:ce:c8:71:c6:fe:a7:81:22:
                    59:b0:72:ab:8d:60:be:10:28:5a:1c:5c:dc:aa:aa:
                    2a:57
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                TinyCA Generated Certificate
            X509v3 Subject Key Identifier: 
                02:2F:7D:16:FC:68:75:EA:A8:D4:EA:C1:E2:AC:7C:D6:F4:BF:AB:21
            X509v3 Authority Key Identifier: 
                keyid:4E:50:43:B6:06:FD:DA:75:17:A0:F3:22:D2:25:71:65:C9:59:0E:05
                DirName:/C=GB/ST=FunkSTate/L=FunkLocality/O=FUNKNET/OU=FunkOU/CN=FUNKNET/emailAddress=ca@funknet.org
                serial:87:C5:A9:41:03:56:AB:E0

            X509v3 Issuer Alternative Name: 
                email:ca@funknet.org
            X509v3 Subject Alternative Name: 
                email:blankserver@funknet.org
    Signature Algorithm: md5WithRSAEncryption
        00:47:0f:3c:88:8e:22:6c:e4:9c:c7:29:44:5f:b3:43:d1:31:
        c2:1b:4f:3b:43:59:76:01:47:95:4a:43:6a:b3:66:bc:9c:77:
        74:71:7b:2a:5a:3d:6e:42:a0:38:ab:7c:41:f3:fb:74:93:bd:
        97:e4:9b:db:bd:e3:98:68:f5:4e:2f:50:8a:9d:44:06:cf:c2:
        53:62:36:e1:70:a0:01:a8:fe:98:9f:31:9f:09:ab:8e:78:7f:
        ad:62:6f:be:6c:d9:0e:88:39:5f:15:e7:29:1d:78:4c:5d:62:
        3f:61:5f:e3:cb:01:da:32:64:1a:55:66:09:5b:27:d9:c8:35:
        4f:01:b6:ff:60:2b:79:87:7b:76:8b:d6:ac:96:8e:71:f3:02:
        84:a8:1a:57:49:3b:e4:29:7e:5f:fb:9b:aa:66:b1:8b:ff:e8:
        8b:c5:1f:c3:0e:2b:94:7c:a6:17:f6:70:dd:5a:56:7a:7c:02:
        bf:f7:b1:e7:db:0d:53:c4:0c:c0:2b:7e:6d:73:10:7f:46:c1:
        57:fc:22:74:94:c2:bd:c0:d6:e9:be:4b:47:40:a4:18:3c:c2:
        c1:9c:ba:f5:ad:fe:88:61:f9:49:d7:c0:3a:72:0c:ad:8a:84:
        8e:63:35:f2:5e:fc:37:86:47:2c:23:e9:2a:a6:4d:e2:8c:be:
        48:61:ba:f8
-----BEGIN CERTIFICATE-----
MIIFFTCCA/2gAwIBAgIBBTANBgkqhkiG9w0BAQQFADCBjDELMAkGA1UEBhMCR0Ix
EjAQBgNVBAgTCUZ1bmtTVGF0ZTEVMBMGA1UEBxMMRnVua0xvY2FsaXR5MRAwDgYD
VQQKEwdGVU5LTkVUMQ8wDQYDVQQLEwZGdW5rT1UxEDAOBgNVBAMTB0ZVTktORVQx
HTAbBgkqhkiG9w0BCQEWDmNhQGZ1bmtuZXQub3JnMB4XDTA2MDEyOTAyMzkzMloX
DTA3MDEyOTAyMzkzMlowgZkxCzAJBgNVBAYTAkdCMRIwEAYDVQQIEwlGdW5rU1Rh
dGUxFTATBgNVBAcTDEZ1bmtMb2NhbGl0eTEQMA4GA1UEChMHRlVOS05FVDEPMA0G
A1UECxMGRnVua09VMRQwEgYDVQQDEwtCTEFOS3NlcnZlcjEmMCQGCSqGSIb3DQEJ
ARYXYmxhbmtzZXJ2ZXJAZnVua25ldC5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDSn+1iXwdgcb0yiyjXLL21Rskdi5GRgUP9IREDopMoCBPi1UwV
KqUgnVPvwk4Z+JA8AEh+uhBMn70tnNcEo9391z5hf5yz1jdjkUHpXkHjHvwVSC5g
XerZmdJsG4IZk5Ae1riAmLS9aZlPKEULM4nKQFA3Hvogknz/ypkvnPxbn9mkw+vl
IdAGaAKEtGAlV2S8XEJ1mxcHXJPNZRBwr3dWckJ5BCYw70z2bMipTSqIEKyC1KPA
h3hPUa7360xcuYzAvh6Os/JABNTm1JR6KFWh8xEhjSHMAOv1lLusCR9I+QLFUV33
6hHOyHHG/qeBIlmwcquNYL4QKFocXNyqqipXAgMBAAGjggFxMIIBbTAJBgNVHRME
AjAAMBEGCWCGSAGG+EIBAQQEAwIGQDArBglghkgBhvhCAQ0EHhYcVGlueUNBIEdl
bmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUAi99Fvxodeqo1OrB4qx81vS/
qyEwgcEGA1UdIwSBuTCBtoAUTlBDtgb92nUXoPMi0iVxZclZDgWhgZKkgY8wgYwx
CzAJBgNVBAYTAkdCMRIwEAYDVQQIEwlGdW5rU1RhdGUxFTATBgNVBAcTDEZ1bmtM
b2NhbGl0eTEQMA4GA1UEChMHRlVOS05FVDEPMA0GA1UECxMGRnVua09VMRAwDgYD
VQQDEwdGVU5LTkVUMR0wGwYJKoZIhvcNAQkBFg5jYUBmdW5rbmV0Lm9yZ4IJAIfF
qUEDVqvgMBkGA1UdEgQSMBCBDmNhQGZ1bmtuZXQub3JnMCIGA1UdEQQbMBmBF2Js
YW5rc2VydmVyQGZ1bmtuZXQub3JnMA0GCSqGSIb3DQEBBAUAA4IBAQAARw88iI4i
bOScxylEX7ND0THCG087Q1l2AUeVSkNqs2a8nHd0cXsqWj1uQqA4q3xB8/t0k72X
5JvbveOYaPVOL1CKnUQGz8JTYjbhcKABqP6YnzGfCauOeH+tYm++bNkOiDlfFecp
HXhMXWI/YV/jywHaMmQaVWYJWyfZyDVPAbb/YCt5h3t2i9aslo5x8wKEqBpXSTvk
KX5f+5uqZrGL/+iLxR/DDiuUfKYX9nDdWlZ6fAK/97Hn2w1TxAzAK35tcxB/RsFX
/CJ0lMK9wNbpvktHQKQYPMLBnLr1rf6IYflJ18A6cgytioSOYzXyXvw3hkcsI+kq
pk3ijL5IYbr4
-----END CERTIFICATE-----
RAWCERT

$obj = Funknet::Whois::Object->new($rawcert);

ok( !defined $obj, 'parse failed on raw cert');

# "normalise whitespace" -- so we can compare the text
# of the parsed object with the original text.
sub _nw {
    my ($text) = @_;
    $text =~ s/^(\s|\n|\r)+//s;
    $text =~ s/(\s+|\n|\r)+$//s;
    $text =~ s/:\s+/: /sg;
    return "$text\n";
}
