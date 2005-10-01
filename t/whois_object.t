#!/usr/bin/perl
use strict;
use Data::Dumper;
#use Test::More tests => 0;
use Test::More qw/ no_plan /;

BEGIN { use_ok ( 'Funknet::Whois::Object' ); }

# Parsing objects without timestamp: attribute.

# 1: aut-num
my $text = <<'TEXT';

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

my $obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                'parse ok' );
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

my $obj = Funknet::Whois::Object->new($text);

ok( defined $obj,                                'parse ok' );
is( ref $obj,          'Funknet::Whois::Object', 'correct class' );
is( $obj->object_type, 'key-cert',               'correct type' );
is( $obj->object_name, 'PGPKEY-B355A313',        'correct name' );
is( $obj->source,      'FUNKNET',                'source ok' );

my $obj_rawtext = $obj->rawtext();
is( $obj_rawtext,      $rawtext,                 'rawtext ok' );

# Parsing objects with timestamps.

# 1: aut-num with correct timestamp

my $text = <<'TEXT';

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

my $obj = Funknet::Whois::Object->new($text, TimeStamp => 1);

ok( defined $obj,                                'parse ok' );
is( ref $obj,          'Funknet::Whois::Object', 'correct class' );
is( $obj->object_type, 'aut-num',                'correct type' );
is( $obj->object_name, 'AS65001',                'correct name' );
is( $obj->source,      'FUNKNET',                'source ok' );
is( $obj->epoch_time,  1128178140,               'epoch time correct' );

# 1: aut-num with invalid timestamp

my $text = <<'TEXT';

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

my $obj = Funknet::Whois::Object->new($text, TimeStamp => 1);

ok( !defined $obj, 'failed parse ok' );
