#!/usr/local/bin/perl
# Copyright (c) 2003
#	The funknet.org Group.
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

Funknet::Robot

=head1 DESCRIPTION

The specifically mail-robot related parts of the RevUpdate code.  See
Funknet::RevUpdate for the general delegation-checking and dynamic
update code.

=head1 FUNCTIONS

=cut

package Funknet::RevUpdate::Robot;
use strict;

use PGP::Mail;
use IPC::Open3;

my @error;

=head2 new

Initialise config data.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    # keyring path
    # testing 

    if (defined $args{pubring} && -f $args{pubring}) {
	$self->{_pubring} = $args{pubring};
    } else {
	return undef;
    }
    if (defined $args{secring} && -f $args{secring}) {
	$self->{_secring} = $args{secring};
    } else {
	return undef;
    }
    if (defined $args{testing}) {
	$self->{_testing} = $args{testing};
    }
    if (defined $args{envfrom}) {
	$self->{_envfrom} = $args{envfrom};
    } else {
	$self->{_envfrom} = 'auto-inaddr@funknet.org';
    }
    if (defined $args{from}) {
	$self->{_from} = $args{from};
    } else {
	$self->{_from} = 'auto-inaddr@funknet.org';
    }

    # find sendmail

    for my $t (qw(/usr/lib/sendmail /usr/sbin/sendmail /sbin/sendmail)) {
	if( -f $t && -x _ ) {
	    $self->{_sendmail} = $t;
	    last;
	}
    }

    return $self;
}

=head2 process_header 

Given a complete mail message, return a hash containing relevant
parsed header fields. Returns undef if a bounce is detected. 

=cut

sub process_header {
    my ($self, $data) = @_;

    for my $l (split/\n(?=\S)/, $data) {
	$l =~ s/\n[ \t]+(\S)/$1/g;
	if($l =~ /^return-path:\s+<(.*?)>\s*$/i) {
	    $self->{_returnpath} = $1;
	    if(!length $self->{_returnpath}) {
		# a bounce
		return undef;
	    }
	}
	elsif($l =~ /^from:\s+/i) {
	    $self->{_fromline} = _getemails($l);
	}
	elsif($l =~ /^reply-to:\s+/i) {
	    $self->{_replytoline} = _getemails($l);
	}
	elsif($l =~ /^$/) {
	    last;
	}
    }
    return 1;
}

=head2 check_sig 

Given a complete mail message, returns the PGP::Mail object if it
checks out ok, or undef. 

=cut

sub check_sig {
    my ($self, $data) = @_;

    my $pgpargs =
    {
	"no_options" => 1,
	"extra_args" =>
	    [
	     "--no-default-keyring",
	     "--no-auto-check-trustdb",
	     "--keyring" => $self->{_keyring},
	     "--secret-keyring" => $self->{_keyring}.".sec",
	     "--keyserver-options" => "no-auto-key-retrieve",
	    ],
	    "always_trust" => 1,
    };
    
    my $pgp = new PGP::Mail($data, $pgpargs);
    if ($pgp->status eq "good") {
	return $pgp;
    } else {
	return undef;
    }
}

sub reply_mail {
    my ($self, $text, %h) = @_;
    my $subject=defined($h{subject}) ? $h{subject} : "";

    my $to = $self->{_replytoline} || $self->{_fromline};
    unless ($to) {
	return 0;
    }

  my $pid;
    if($self->{_testing}) {
	open(MAIL, ">&STDOUT");
    }
    else {
	eval {
	    $pid=open3(\*MAIL, \*M_OUT, \*M_ERR,
		$self->{_sendmail}, "-bm", "-oi", "-oem",
		"-f", $self->{_envfrom},
		$to
		);
	    };

	return undef if $@;
    }

    # Print out the mail
    print MAIL _header("From", "Reverse Delegation Robot <" . $self->{_from} . ">");
    print MAIL _header("To", $to);
    print MAIL _header("Subject", $subject)
	if(length $subject);
    print MAIL "\n";
    print MAIL $text;

    close MAIL;

    return 1 if($self->{_testing});

    my $m_out=join("", <M_OUT>);
    my $m_err=join("", <M_ERR>);

    close(M_OUT);
    close(M_ERR);

    waitpid($pid, 0);

    return (($?>>8)==0);
}


sub success_text {
    my ($self, $zone, @ns) = @_;
    my $ns_list = join "\n", @ns;

    return << "MAILTEXT";

Funknet Reverse Delegation result:

The zone $zone has been successfully delegated to:
$ns_list

Regards,
Dennis

MAILTEXT

}

sub failure_text {
    my ($self, $zone, @ns) = @_;
    my $ns_list = join "\n", @ns;
    my $errorlist = join "\n", $self->error();
    
    return << "MAILTEXT";

Funknet Reverse Delegation result:

Your request for the delegation of $zone to:
$ns_list

has failed for the following reason(s):
$errorlist

Comiserations,
Dennis

MAILTEXT

}

sub error {
    my ($self, $error_text) = @_;
    if ($error_text) {
	push @error, $error_text;
    } else {
	if (wantarray) {
	    return @error;
	} else {
	    return join ', ',@error;
	}
    }
}

sub fatalerror {
    my ($self, $error_text) = @_;
    my $text = <<"MAILTEXT";

An error occurred processing your reverse delegation request:
$error_text

Sorry it didn't work out.

Regards,
Dennis

MAILTEXT

    $self->reply_mail( $text, subject => "Reverse Delegation error" );
    exit 0;
}

sub _header {
    my $text=shift;

    my $output=$text . ": ";

    while(@_) {
	$output .= shift();
	if(@_) {
	    $output .= ",";
	    $output =~ /^([^\n]*)$/;
	    if(length $1 > 50) {
		$output .= "\n ";
	    }
	    else {
		$output .= " ";
	    }
	}
    }
    return $output . "\n";
}

use vars qw(@DIM
	    $DM_ATOM $DM
	    $LP_ATOM
	    $QTEXT $QP
	    $QUOTED_LP
	    $LP
	    $CTEXT $CCONTENT $COMMENT
	    $PHRASE
	    $UKPC
	    );


# Local-parts of email addresses
$LP_ATOM=qr/ (?: [a-zA-Z0-9!\x23\/\$%\&'*+=?^_`{}|~-]+ ) /x; #' 

#     Quoted local-parts
$QTEXT=qr/ (?: [\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]+ ) /x;
$QP=qr/ (?: \\[\x01-\x09\x0b\x0c\x0e-\x7f] ) /x;
$QUOTED_LP=qr/ (?: " (?: $QP | $QTEXT )* " ) /x;
$CTEXT=qr/ (?: [\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x27\x2a-\x5b\x5d-\x7f] ) /x;
$CCONTENT=qr/
             (?:
		 $CTEXT |
		 $QP |
		 \(\s* (?:
		     $CTEXT |
		     $QP |
		     \(\s* (?:
			 $CTEXT |
			 $QP
		     )
		     \s*\)
		 )
		 \s*\)
	     ) /x;
$LP=qr/ (?: (?: $LP_ATOM (?: \.$LP_ATOM )* ) | $QUOTED_LP )/x;
$DM_ATOM=qr/ (?: [a-z0-9] (?: [a-z0-9-]*[a-z0-9] )? ) /xi;
$DM=qr/ (?: $DM_ATOM (?: \.$DM_ATOM )* \.?  ) /x;
$COMMENT=qr/ (?: \s* \( (?: \s* $CCONTENT )* \s*\) \s* | \s* ) /x;
$PHRASE=qr/ (?: $COMMENT* (?: (?: $LP_ATOM | $QUOTED_LP ) $COMMENT* )* ) /x;


sub _getemails {
    my $header = shift;

    $header =~ s/^[^:]+:\s+//;
    $header =~ s/\s*$//;

    my @email=();
    while(length $header) {
	if($header =~
	    s/^ $COMMENT* $PHRASE* < ($LP \@ $DM) > $COMMENT* (?:, (.*))?$/
		defined $2 ? $2 : ""
		/xe) {
	    push(@email, $1);
	}
	elsif($header =~
	    s/^ $COMMENT* ($LP \@ $DM) $COMMENT* (?:, (.*))?$/
		defined $2 ? $2 : ""
		/xe) {
	    push(@email, $1);
	}
	else {
	    # invalid header line
	    return ();
	}
    }
    return @email[0];
}


1;
