# Copyright (c) 2004
#       The funknet.org Group.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#       This product includes software developed by The funknet.org
#       Group and its contributors.
# 4. Neither the name of the Group nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE GROUP AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE GROUP OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

=head1 NAME 

Funknet::KeyStash::CertServer

=head1 DESCRIPTION

Implements the cert generation and signing parts of the KeyStash system.

=over 4

=item Generating requests on behalf of users

=item Signing requests

=item Generating appropriate output formats (PKCS#12)

=back

This code is ripped from OpenSSL's CA.pl, and doesn't try to be more
clever than to just shell out to the openssl binary.

=head1 SYNOPSIS

  use Funknet::KeyStash::CertServer;
  my $cs = Funknet::KeyStash::CertServer->new('etc/ca', 'TestCA');

  my ($newkey, $newreq) = $cs->newreq( cn         => 'TestCN',
                                       ou         => 'TestOU',
                                       passphrase => 'xyzzy',
                                     );

  my $newcert = $cs->sign( req          => $newreq,
                           capassphrase => 'verysecretpassphrase',
                         );

  my $newp12 = $cs->pkcs12( exportpass => 'blahblah',
                            passphrase => 'xyzzy',
                            key        => $newkey,
                            cert       => $newcert,
                         );

=head1 METHODS

=cut

package Funknet::KeyStash::CertServer;
use strict;
use Expect;

=head2 new

Constructor for a CertServer object. Specify the path to the CAs
directory, and the CA to work with - this will look for a file named
$CA.cnf specifying the OpenSSL config required.

=cut

sub new {
    my ($class, $path, $ca) = @_;
    my $self = bless {}, $class;

    my $cnf = "$ca.cnf";

    unless ( -f "$path/$cnf" ) {
        return undef;
    }

    $self->{_ca}     = $ca;
    $self->{_config} = $cnf;
    $self->{_path}   = $path;
    return $self;
}

=head2 newreq

Given a Common Name, an OU and the private key passphrase for the new
key, generates a CSR using the openssl tools. 

Params: 
    cn: the Common Name for the cert's DN
    ou: the Organisational Unit for the cert's DN
    passphrase: the passphrase for the associated private key.

Returns:
    list, the key then the CSR.

=cut

sub newreq {
    my ($self, %args) = @_;

    unless (defined $args{cn}) {
        warn "no cn specified in newreq";
        return undef;
    }
    unless (defined $args{ou}) {
        warn "no ou specified in newreq";
        return undef;
    }
    unless (defined $args{passphrase}) {
        warn "no passphrase specified in newreq";
        return undef;
    }

    # make a work directory for openssl
    my $workdir = "$self->{_path}/ca_tmp_$$";
    system("mkdir $workdir");

    my $exp = new Expect;
    $exp->raw_pty(0);
    $exp->log_stdout(0);
    my $ret = $exp->spawn("openssl req -config $self->{_path}/$self->{_config} -new -keyout $workdir/newreq.pem ". 
                          "-out $workdir/newreq.pem -days 365");
    unless ($ret) {
        warn "can't spawn newreq $!";
        return undef;
    }

    $exp->expect(
                 60,
                 [
                  qr'Enter PEM pass phrase:',
                  sub {
                      my $fh = shift;
                      $fh->send("$args{passphrase}\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'Verifying password - Enter PEM pass phrase:',
                  sub {
                      my $fh = shift;
                      $fh->send("$args{passphrase}\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'Country Name \(2 letter code\) \[.*\]:',
                  sub {
                      my $fh = shift;
                      $fh->send("\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'State or Province Name \(full name\) \[.*\]:',
                  sub {
                      my $fh = shift;
                      $fh->send("\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'Locality Name \(eg, city\) \[.*\]:',
                  sub {
                      my $fh = shift;
                      $fh->send("\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'Organization Name \(eg, company\) \[.*\]:',
                  sub {
                      my $fh = shift;
                      $fh->send("\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'Organizational Unit Name \(eg, section\) \[\]:',
                  sub {
                      my $fh = shift;
                      $fh->send("$args{ou}\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'Common Name \(.*\) \[\]:',
                  sub {
                      my $fh = shift;
                      $fh->send("$args{cn}\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'Email Address \[\]:',
                  sub {
                      my $fh = shift;
                      $fh->send("\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'A challenge password \[\]:',
                  sub {
                      my $fh = shift;
                      $fh->send("\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'An optional company name \[\]:',
                  sub {
                      my $fh = shift;
                      $fh->send("\n");
                      exp_continue;
                  }
                 ],
                 [
                  timeout =>
                  sub {
                      warn "timeout.\n";
                  }
                 ]
                );
    
    # req is now in path/ca_tmp_$$/newreq.pem. 

    my $reqfile = "$workdir/newreq.pem";
    unless (open REQ, $reqfile) {
        warn "couldn't open $reqfile: $!";
        return undef;
    }
    my $reqtext;
    {
        local $/ = undef;
        $reqtext = <REQ>;
    }
    close REQ;
    unless (defined $reqtext) {
        warn "0 length newreq.pem";
        return undef;
    }
    
    # clear up. we don't keep track of requests; that's the caller's job.
    system("rm -Rf $self->{_path}/ca_tmp_$$/");

    # separate req and key

    my ($key, $req) = $reqtext =~ /(-----BEGIN RSA PRIVATE KEY-----.*-----END RSA PRIVATE KEY-----)\n(-----BEGIN CERTIFICATE REQUEST-----.*-----END CERTIFICATE REQUEST-----)/s;

    return ($key, $req);
}

=head2 sign

Signs a certificate request.

Params:
    capassphrase: the CA private key passphrase
    req: the CSR text.

Returns:
    the signed cert

=cut

sub sign {
    my ($self, %args) = @_;

    unless (defined $args{capassphrase}) {
        warn "no capassphrase specified in sign";
        return undef;
    }
    unless (defined $args{req}) {
        warn "no req specified in sign";
        return undef;
    }

    # change into the correct directory for the CA
    my $old = `pwd`;
    chop $old;
    unless (chdir $self->{_path}) {
        warn "couldn't chdir to $self->{_path}: $!";
        return undef;
    }

    # make a work directory for openssl
    my $workdir = "ca_tmp_$$";
    system("mkdir $workdir");

    # put the req in the workdir
    unless (open REQ, ">$workdir/newreq.pem") {
        warn "can't open $workdir/newreq.pem for writing: $!";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }
    print REQ $args{req};
    close REQ;

    my $exp = new Expect;
    $exp->raw_pty(0);
    $exp->log_stdout(0);
    my $ret = $exp->spawn("openssl ca -config $self->{_config} -policy policy_anything -out $workdir/newcert.pem -infiles $workdir/newreq.pem");
    unless ($ret) {
        warn "can't spawn sign $!";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }

    $exp->expect(
                 60,
                 [
                  qr'Enter .*:',
                  sub {
                      my $fh = shift;
                      $fh->send("$args{capassphrase}\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'Sign the certificate\? \[y/n\]:',
                  sub {
                      my $fh = shift;
                      $fh->send("y\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'1 out of 1 certificate requests certified, commit\? \[y/n\]',
                  sub {
                      my $fh = shift;
                      $fh->send("y\n");
                      exp_continue;
                  }
                 ],
                 [
                  timeout =>
                  sub {
                      warn "timeout.\n";
                  }
                 ]
                );

    # signed cert is now in path/ca_tmp_$$/newcert.pem. 

    my $certfile = "$workdir/newcert.pem";
    unless (open CERT, $certfile) {
        warn "couldn't open $certfile: $!";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }
    my $certtext;
    {
        local $/ = undef;
        $certtext = <CERT>;
    }
    close CERT;
    unless (defined $certtext) {
        warn "0 length newcert.pem";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }
    
    # clear up. we don't keep track of cert output; that's the caller's job.
    system("rm -Rf $workdir");
    unless (chdir $old) {
        warn "couldn't chdir to $old: $!";
    }

    my ($cert) = $certtext =~ /(-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----)/s;
    return $cert;
}

=head2 pkcs12

Takes a PEM cert and key, and returns a PKCS#12 file

Params: 
    passphrase: the passphrase on the private key
    exportpass: the export passphrase for the PKCS#12 file
    key: the private key text in PEM format
    cert: the certificate in PEM format

Returns: 
    the PKCS#12 file (binary!)

=cut

sub pkcs12 {
    my ($self, %args) = @_;

    unless (defined $args{passphrase}) {
        warn "no passphrase specified in sign";
        return undef;
    }
    unless (defined $args{exportpass}) {
        warn "no exportpass specified in sign";
        return undef;
    }
    unless (defined $args{key}) {
        warn "no key specified in sign";
        return undef;
    }
    unless (defined $args{cert}) {
        warn "no cert specified in sign";
        return undef;
    }

    # change into the correct directory for the CA
    my $old = `pwd`;
    chomp $old;
    unless (chdir $self->{_path}) {
        warn "couldn't chdir to $self->{_path}: $!";
        return undef;
    }

    # make a work directory for openssl
    my $workdir = "ca_tmp_$$";
    system("mkdir $workdir");

    # put the key in the workdir
    unless (open KEY, ">$workdir/new.key") {
        warn "can't open $workdir/new.key for writing: $!";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }
    print KEY $args{key};
    close KEY;

    # put the cert in the workdir
    unless (open CERT, ">$workdir/new.cert") {
        warn "can't open $workdir/new.cert for writing: $!";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }
    print CERT $args{cert};
    close CERT;

    my $exp = new Expect;
    $exp->raw_pty(0);
    $exp->log_stdout(0);
    my $ret = $exp->spawn("openssl pkcs12 -export -in $workdir/new.cert -inkey $workdir/new.key -certfile $self->{_ca}/cacert.pem -out $workdir/new.p12"); 
    unless ($ret) {
        warn "can't spawn pkcs12: $!";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }

    $exp->expect(
                 60,
                 [
                  qr'Enter pass phrase for .*/new.key:',
                  sub {
                      my $fh = shift;
                      $fh->send("$args{passphrase}\n");
                      exp_continue;
                  }
                 ],
                 [
                  qr'Enter Export Password:',
                  sub {
                      my $fh = shift;
                      $fh->send("$args{exportpass}\n");
                      exp_continue;
                  }
                 ],
                 [
                  timeout =>
                  sub {
                      warn "timeout.\n";
                  }
                 ]
                );

    # signed cert is now in path/ca_tmp_$$/newcert.pem. 

    my $pkcs12file = "$workdir/new.p12";
    unless (open PKCS, $pkcs12file) {
        warn "couldn't open $pkcs12file: $!";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }
    my $pkcs12text;
    {
        local $/ = undef;
        $pkcs12text = <PKCS>;
    }
    close PKCS;
    unless (defined $pkcs12text) {
        warn "0 length new.p12"; 
	system("rm -Rf $workdir");
	chdir $old;
	return undef;
    }
    
    # clear up. we don't keep track of cert output; that's the caller's job.
    system("rm -Rf $workdir");
    chdir $old;

    return $pkcs12text;
}    

=head2 object

Takes a PEM cert and returns the basis for a whois object
Doesn't bother with the contacts, mntner etc. 

Params: 
    cert: the certificate in PEM format

Returns: 
    part of a key-cert object. 

=cut

sub object {
    my ($self, $cert) = @_;
    my $object;
    
    # change into the correct directory for the CA
    my $old = `pwd`;
    chop $old;
    unless (chdir $self->{_path}) {
        warn "couldn't chdir to $self->{_path}: $!";
        return undef;
    }

    # make a work directory for openssl
    my $workdir = "ca_tmp_$$";
    system("mkdir $workdir");

    # put the cert in the workdir
    unless (open CERT, ">$workdir/whois.cert") {
        warn "can't open $workdir/whois.cert for writing: $!";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }
    print CERT $cert;
    close CERT;

    # call to openssl
    my @output = `openssl x509 -in $workdir/whois.cert -subject`;
    unless (scalar @output) {
	warn "openssl x509 failed: $!";
	system("rm -Rf $workdir");
	chdir $old;
	return undef;
    }
    my $dn = $output[0];
    chomp $dn;
    
    # grab the cn from the dn string, e.g.
    # subject= /C=GB/ST=London/L=London/O=Funknet.org/OU=FooCo/CN=FooBox
    my ($cn) = $dn =~ m!CN=([^/]+)!i;
    unless (defined $cn) {
	warn "couldn't parse cn from $dn";
	system("rm -Rf $workdir");
	chdir $old;
	return undef;
    }

    # remove the subject=
    $dn =~ s/^subject= /X509CERT-/;

    # prepend all the lines of the cert with certif:
    $cert =~ s/\n/\ncertif:    /g;
    $cert = "certif:    $cert";
    
    # assemble the object
    $object = <<"OBJ";
key-cert:  $dn
method:    X509
owner:     $cn
$cert
OBJ

    # clear up. we don't keep track of cert output; that's the caller's job.
    system("rm -Rf $workdir");
    chdir $old;
    
    return $object;
}

=head2 nodes

Takes an encrypted key and returns it unencrypted.

Params: 
    key: the certificate in PEM format
    passphrase: the key passphrase

Returns: 
    the unencrypted key

=cut


sub nodes {
    my ($self, %args) = @_;

    unless (defined $args{passphrase}) {
        warn "no passphrase specified in sign";
        return undef;
    }
    unless (defined $args{key}) {
        warn "no key specified in sign";
        return undef;
    }

    # change into the correct directory for the CA
    my $old = `pwd`;
    chomp $old;
    unless (chdir $self->{_path}) {
        warn "couldn't chdir to $self->{_path}: $!";
        return undef;
    }

    # make a work directory for openssl
    my $workdir = "ca_tmp_$$";
    system("mkdir $workdir");

    # put the key in the workdir
    unless (open KEY, ">$workdir/new.key") {
        warn "can't open $workdir/new.key for writing: $!";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }
    print KEY $args{key};
    close KEY;

    my $exp = new Expect;
    $exp->raw_pty(0);
    $exp->log_stdout(0);
    my $ret = $exp->spawn("openssl rsa -in $workdir/new.key -out $workdir/new.key.un"); 
    unless ($ret) {
        warn "can't spawn openssl rsa: $!";
        return undef;
    }

    $exp->expect(
                 60,
                 [
                  qr'Enter pass phrase for .*/new.key:',
                  sub {
                      my $fh = shift;
                      $fh->send("$args{passphrase}\n");
                      exp_continue;
                  }
                 ],
                 [
                  timeout =>
                  sub {
                      warn "timeout.\n";
                  }
                 ]
                );

    # unencrypted key is now in path/ca_tmp_$$/new.key.un
    my $unkeyfile = "$workdir/new.key.un";
    unless (open KEY, $unkeyfile) {
        warn "couldn't open $unkeyfile: $!";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }
    my $keytext;
    {
        local $/ = undef;
        $keytext = <KEY>;
    }
    close KEY;
    unless (defined $keytext) {
        warn "0 length new.key.un";
	system("rm -Rf $workdir");
	chdir $old;
        return undef;
    }
    
    system("rm -Rf $workdir");
    chdir $old;
    return $keytext;
}
    
1;
