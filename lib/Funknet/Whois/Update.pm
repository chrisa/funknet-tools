# Copyright (c) 2004
#      The funknet.org Group.
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
#	This product includes software developed by The funknet.org
#	Group and its contributors.
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

Funknet::Whois::Updater

=head1 DESCRIPTION

Use Email::Robot to implement a pureperl whois-by-email updater.

=head1 FUNCTIONS

=cut

package Funknet::Whois::Update;
use strict;

use Funknet::Whois qw/ parse_object check_auth /;
use Funknet::Whois::Update::Robot;
use Fcntl qw/ :DEFAULT :flock :seek /;
use Data::Dumper;

=head2 new

Constructor. set up an updater for the right source. 

=cut

sub new {
    my ($class, $source, $verbose) = @_;
    my $self = bless {}, $class;
    
    unless (defined $source) {
	warn "need a source";
	return undef;
    }

    $self->{_verbose} = $verbose;
    $self->{_source} = $source;
    $self->{_testing} = 1;
    
    return $self;
}

=head2 update

Main entry point for update routine. Stolen from auto-inaddr.pl.

=cut

sub update {
    my ($self, $file) = @_;

    # read mail, spin up Robot

    my $data;
    my $line = <STDIN>;
    if($line && $line !~ /^From /) {
	$data .= $line;
    }
    while(read(STDIN, $line, 8192)) {
	$data .= $line;
    }

    my $robot = Funknet::Whois::Update::Robot->new( fromname => 'auto-dbm robot', 
						    envfrom  => 'auto-dbm@funknet.org',
						    from     => 'auto-dbm@funknet.org',
						    pubring  => '/home/dunc/.gnupg/pubring.gpg',
						    secring  => '/home/dunc/.gnupg/secring.gpg',
						    testing  => $self->{_testing},
						  );
    if (!$robot) {
	errorlog("couldn't create FWU::Robot\n");
	exit 1;
    }

    unless ($robot->process_header($data)) {
	errorlog("error reading header -- a bounce?");
	exit 0;    
    }

    # check pgp sig

    my $pgp;
    unless ($pgp = $robot->check_sig($data)) {
	$robot->fatalerror("no valid and known signature found");
    }

    # attempt to create a Net::Whois::RIPE::Object

    my @objects;
    for my $text (split /\n\n/, $pgp->data) {
	if (my $object = parse_object($text)) {
	    push @objects, $object;
	}
    }
    if (scalar @objects == 0) {
	warn "no objects";
	$robot->fatalerror("couldn't convert the signed message into any Net::WHOIS::RIPE::Objects");	
    }

    # check authorisation and source against whois.

    my (@ok, @noauth, @nosource);
    for my $object (@objects) {
	if ($object->source ne $self->{_source}) {
	    warn "no source";
	    push @nosource, $object;
	    next;
	}

	# de-MBM the key id (we do *not* want 64 bit keyids, tyvm)
	my $keyid64 = $pgp->keyid;
	my ($keyid32) = $keyid64 =~ /([A-Z0-9]{8})$/i;

	if (check_auth($object, $keyid32)) {
	    push @ok, $object;
	} else {
	    warn "auth fail";
	    $robot->error("hierarchical authorisation failed for object ".$object->object);
	    push @noauth, $object;
	}
    }

    # apply the authorised objects (lock datafile, load existing to hash, replace, write, unlock)
    
    unless (sysopen DATA, "$file", O_RDWR) {
	warn "couldn't open $file for read/write: $!";
	return undef;
    }
    unless (flock DATA, LOCK_EX|LOCK_NB) {
	warn "couldn't lock $file: $!";
	return undef;
    }
    
    my ($currobj, $objects);
    while (my $line = <DATA>) {
	chomp $line;
	next if $line =~ /^#/;
	if ($line =~ /^(.*): (.*)$/) {

	    my ($key, $value) = ($1, $2);
	    $key =~ s/ //g;
	    $value =~ s/ //g;

	    if ($key eq 'source' && $value ne $self->{_source}) {
		undef $currobj;
		next;
	    }
	    unless (defined $currobj) {
		$currobj->{type} = $key;
		$currobj->{name} = $value;
		$currobj->{text} = "$line\n";
	    } else {
		$currobj->{text} .= "$line\n";
	    }
	} else {
	    $objects->{$currobj->{type}}->{$currobj->{name}} = $currobj->{text};
	    undef $currobj;
	}
    }

    for my $object (@ok) {
	$objects->{$object->type}->{$object->name} = $object->text;
    }

    unless(seek DATA, 0, SEEK_SET) {
	warn "couldn't seek: $!";
	return undef;
    }
    
    for my $type (keys %$objects) {
	for my $name (keys %{$objects->{$type}}) {
	    print DATA $objects->{$type}->{$name}, "\n";
	}
    }
    
    flock (DATA, LOCK_UN);
    close DATA;


    # reply.

    my @failed = (@noauth, @nosource);

    if (scalar (@failed)) {
	my $mail_text = $robot->failure_text($pgp->keyid, $robot->header_text, @objects);
	unless (my $res = $robot->reply_mail( $mail_text, subject => 'FAILED: ' )) {
	    errorlog("error sending mail: $res");
	    exit 1;
	}
    }

    if (scalar (@ok)) {
	my $mail_text = $robot->success_text($pgp->keyid, $robot->header_text, @objects);
	unless (my $res = $robot->reply_mail( $mail_text, subject => 'SUCCEEDED: ' )) {
	    errorlog("error sending mail: $res");
	    exit 1;
	}
    }
	
}

sub errorlog {
    my ($log_text) = @_;
    print STDERR $log_text;
}


1;
