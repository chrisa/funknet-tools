#!/usr/local/bin/perl -w
use strict;
use Funknet::Whois::ObjectGenerator;

# get a blank generator object, and make an unmaintained person. 

my $gen = Funknet::Whois::ObjectGenerator->new( source => 'FUNKNET' );
my $me = $gen->person( 'name'    => 'Me',
		       'address' => [ 'Some', 'Where' ],
		       'e_mail'  => 'me@example.com',
		       'phone'   => '23785542312',
                       );

print scalar $me->text;

my $key = $gen->key_cert( 'name'    => 'PGPKEY-XXXXXXXX',
			  'e_mail'  => 'me@example.com',
			  'certif'  => '-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.2.1 (Darwin)

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
ETF8540NSSd83GgAn060xCOHdFN4wFcWLiwnBsuiUXENiEYEExECAAYFAj5rSQ4A
CgkQbOExbr3XbTcwEQCfYbIdVA90y0zOMksY9ZpnWsjCoNgAnRr4hBI8wA9rXc1w
Ils65Xsjal8OiEYEEBECAAYFAj5qLxQACgkQHuunYz0wn8LO1wCgn3r5KlJOe075
nFG20UMlB9XI5yEAn2co/Ba3v8CsDygTuq+GXo/K8o4UiEYEExECAAYFAj8ft6EA
CgkQryCulZr3rzBoUwCg1SEAQjJsbVpNWmaMd0aoGpSFwEQAoJ7muebZiysGNIzv
M/rOrN1tO8EFiEYEExECAAYFAj88zGEACgkQYf/Cj3bukkgfJgCeP1l/rA+9UtG5
zDcQigjIFiwi7jwAoKZspZR1uco1clRQsDhzfizu2XmDiEYEExECAAYFAj88yg4A
CgkQpQ4p2TvRQNAPtQCcDPJpxMsL5sqGRegQYl9UuqrkU2UAoNmNRijcK8MOku27
ynxBYu+noD0cuQENBD1FPlQQBAC+nIFIhG4eBAJuMHcyRts3NLLfSWiCZjFWTc5O
hQIrz53GKnkkRFwDh5Dp84wAXv9cmqrsOX+VugO4WWMtMFfr2f0XGcCMLZBdaYzz
+wyKHVQLuCf7SthweMmqaCeznYtOwbSfacjagLB7IlOrS2oPm6zs+K7KVNiwxuBy
TAyfZwAEDQP/c2qu7Yhnpxyuyj8NYv7eQxTP1fUytJUrQO89hLLF+BapkROmE8c7
gq4W1pYMBL3OCpLRIGzoQUK34do4rhwi0d4YpJNuWsxQr75eoIpY/NVKm1rqJ1l8
yMl8Rg/3tNvtPcwdsFF1nJWIQKitWxZZglmliw6RIv9rA5pZPOeyLa2IRQQYEQIA
BgUCPUU+VAAKCRBFoeiQs1WjEz+9AJ48dKfDmM3fm4yYRr8nDYCaLBlO3gCY5WoF
kwVKmMBxJt3NH4C//xffVw==
=D0VL
-----END PGP PUBLIC KEY BLOCK-----
',
		      );

print scalar $key->text;

# get a generator with that person, and make a maintainer. 

my $gen = Funknet::Whois::ObjectGenerator->new('source' => 'FUNKNET', 
					       'person' => 'CA1-FUNKNET' );

my $me = $gen->mntner( 'name'    => 'MY-MUNTER', 'auth' => 'PGPKEY-B355A313',
		       'descr'   => 'test munter', 'e_mail' => 'foo@bar.com' );

print scalar $me->text;

