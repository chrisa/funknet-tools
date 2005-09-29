# Copyright (c) 2005
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

use Funknet::Whois::Client;
use Funknet::Whois::ObjectFile;
use Funknet::Whois::Update::Robot;
use Data::Dumper;

=head2 new

Constructor. set up an updater for the right source. 

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    
    unless (defined $args{source}) {
	warn "need a source";
	return undef;
    }
    unless (defined $args{objfile}) {
	warn "need an objects file";
	return undef;
    }

    # basics
    $self->{_verbose} = $args{verbose};
    $self->{_source}  = $args{source};
    $self->{_testing} = $args{testing};
    $self->{_objfile} = $args{objfile};

    # server
    $self->{_host}    = $args{listen_address};
    $self->{_port}    = $args{listen_port};

    # gpg
    $self->{_pubring} = $args{pubring};
    $self->{_secring} = $args{secring};

    # mail
    $self->{_fromname} = $args{fromname};
    $self->{_envfrom}  = $args{envfrom};
    $self->{_from}     = $args{from};

    if ($self->{_verbose}) {
	print STDERR Dumper $self;
    }

    return $self;
}

=head2 update

Main entry point for update routine. Stolen from auto-inaddr.pl.

=cut

sub update {
    my ($self) = @_;

    # read mail, spin up Robot

    my $data;
    my $line = <STDIN>;
    if($line && $line !~ /^From /) {
	$data .= $line;
    }
    while(read(STDIN, $line, 8192)) {
	$data .= $line;
    }

    my $robot = Funknet::Whois::Update::Robot->new( fromname => $self->{_fromname},
						    envfrom  => $self->{_envfrom},
						    from     => $self->{_from},
						    pubring  => $self->{_pubring},
						    secring  => $self->{_secring},
						    testing  => $self->{_testing},
						  );
    if (!$robot) {
	errorlog("couldn't create FWU::Robot\n");
	exit 1;
    }

    if ($self->{_verbose}) {
	print STDERR Dumper $robot;
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

    # de-MBM the key id (we do *not* want 64 bit keyids, tyvm)
    my $keyid64 = $pgp->keyid;
    my ($keyid32) = $keyid64 =~ /([A-Z0-9]{8})$/i;

    # attempt to create a Funknet::Whois::Object

    my @objects;
    for my $text (split /\r?\n\r?\n/, $pgp->data) {
	if (my $object = Funknet::Whois::Object->new($text)) {
	    push @objects, $object;
	}
    }
    if (scalar @objects == 0) {
	warn "no objects";
	$robot->fatalerror("couldn't convert the signed message into any Funknet::Whois::Object objs.");
    }
    
    # check authorisation and source against whois.

    # first get a FWC.
    my $client = Funknet::Whois::Client->new( $self->{_host}, Port => $self->{_port} );
    
    for my $object (@objects) {
	if ($object->source ne $self->{_source}) {
	    $object->error("incorrect source: ".$object->source);
	    next;
	}

	if ($client->check_auth($object, $keyid32)) {
	    # nothing
	} else {
	    $object->error("hierarchical authorisation failed for object ".$object->object);
	}
    }

    # apply the authorised objects (lock datafile, load existing to hash, replace, write, unlock)

    my $object_file = Funknet::Whois::ObjectFile->new( filename => $self->{_objfile},
                                                       source   => $self->{_source},
                                                     );
    my $num = $object_file->load();
    
    my $objects;
    for my $object ($object_file->objects()) {
        $objects->{$object->object_type}->{$object->object_name} = $object;
    }
    
    my $fail    = 0;
    my $success = 0;

    for my $object (@objects) {
	if ($object->error()) {
	    $fail++;
	} else {
	    $success++;
	    if (defined $object->delete()) {
		$objects->{$object->object_type}->{$object->object_name} = undef;
	    } else {
		$objects->{$object->object_type}->{$object->object_name} = $object;
	    }
	}
    }
    
    $object_file->save($objects);

    # reply.

    if ($fail > 0) {
	my $mail_text = $robot->failure_text($keyid32, $robot->header_text, @objects);
	unless (my $res = $robot->reply_mail( $mail_text, subject => 'FAILED: ' )) {
	    errorlog("error sending mail: $res");
	    exit 1;
	}

    } else {

	my $mail_text = $robot->success_text($keyid32, $robot->header_text, @objects);
	unless (my $res = $robot->reply_mail( $mail_text, subject => 'SUCCEEDED: ' )) {
	    errorlog("error sending mail: $res");
	    exit 1;
	}
    }
    
    return ($success);
}

sub errorlog {
    my ($log_text) = @_;
    print STDERR $log_text;
}


1;
