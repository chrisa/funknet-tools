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

Funknet::KeyStash::Client

=head1 DESCRIPTION

Client for retrieving certificates and secret keys from the
keystash. Implements two methods, get_key and get_cert, which check
the local stash, then query the whois (for certs) or the secure remote
keystash web server (for keys). 

Both methods return the raw key or cert data, stripped of certif:
whois lines in the case of whois objects. If the object is not found
either locally or on the servers, the the methods both return undef.

If the object is found, then a copy will be written locally, using the
name which was queried for. Certs are stored in $ks_path/certs/, and
keys in $ks_path/keys/. 

=head2 METHODS

=cut

package Funknet::KeyStash::Client;
use base qw/ Funknet::KeyStash /;
use strict;
use LWP::UserAgent;
use HTTP::Request;
use URI::Escape;
use IO::Scalar;
use Funknet::Whois qw/ get_object /;
use Funknet::Whois::Client;
use Funknet::Whois::Object;

use Data::Dumper;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    
    unless (defined $args{www_user} &&
	    defined $args{www_pass} &&
	    defined $args{www_host} &&
	    defined $args{www_cert} &&
	    defined $args{www_ca} &&
	    defined $args{path} &&
	    defined $args{whois_host} &&
	    defined $args{whois_port} &&
	    defined $args{whois_source}
	   ) {
	return undef;
    }

    $self->{_www_user} = $args{www_user};
    $self->{_www_pass} = $args{www_pass};
    $self->{_www_host} = $args{www_host};
    $self->{_www_cert} = $args{www_cert};
    $self->{_www_ca}   = $args{www_ca};

    $self->{_path} = $args{path};

    $self->{_whois_host}   = $args{whois_host};
    $self->{_whois_port}   = $args{whois_port};
    $self->{_whois_source} = $args{whois_source};
    
    $self->{_ua} = new LWP::UserAgent;
    return $self;
}

=head2 get_key

return the specified private key, by CN.

looks in the local keystash, then tries the server. if the key is
found on the server, it's cached locally. in either case, the raw key
material itself is returned, for writing into the ipsec config.

=cut

sub get_key {
    my ($self, $cn) = @_;

    # check local keystash
    if (my $data = $self->_check_file('key', $cn)) {
	return $data;
    }
    
    # give up and retrieve the key from the server.
    my $uri_cn = uri_escape($cn);
    my $uri = "https://$self->{_www_host}/keystash/$uri_cn";
    my $req = HTTP::Request->new('GET', $uri);
    $req->authorization_basic($self->{_www_user}, $self->{_www_pass});
    my $res = $self->{_ua}->request($req);

    if ($res->code == 200) {
	my $issuer  = $res->header("client-ssl-cert-issuer");
	my $subject = $res->header("client-ssl-cert-subject");
	
	if ($subject eq $self->{_www_cert} &&
	    $issuer  eq $self->{_www_ca} ) 
	  {
	      my $key = $res->message;
	      
	      # write a local copy
	      $self->_write_file('key',$cn,$key);
	      
	      return $key;
	  } else {
	      $self->warn("https subject/issuer mismatch");
	      return undef;
	  }
    } else {
	$self->warn("https get failed for $cn");
	return undef;
    }
}
    

=head2 get_cert

return the specified private cert, by  whois name or CN

looks in the local keystash, then tries the server. if the cert is
found on the server, it's cached locally. in either case, the raw cert
material itself is returned, for writing into the ipsec config.

=cut

sub get_cert {
    my ($self, $name) = @_;

    # check local keystash
    if (my $data = $self->_check_file('cert', $name)) {
	my $object = Funknet::Whois::Object->new($data);
	return $object;
    }
    
    # give up and retrieve the key from the server.
    my $fwc = Funknet::Whois::Client->new($self->{_whois_host}, 
					  Port    => $self->{_whois_port},
					  Timeout => 10);
    $fwc->source($self->{_whois_source});
    $fwc->type('key-cert');
    my $cert = $fwc->query($name);

    if (!defined $cert) {
	$self->warn("certificate not found: $name");
	return undef;
    } else {
	my $certtext = $cert->text;

	# write a local copy
	$self->_write_file('cert',$name,$certtext);

	return $cert;
    }

}
 
sub _check_file {
    my ($self, $type, $name) = @_;
    my $path = "$self->{_path}/$type/$name";
    
    if ( -f $path ) {
	unless (open IN, "$path") {
	    $self->warn("couldn't open $path for reading: $!");
	    return undef;
	}
	my $data;
	{
	    local $/ = undef;
	    $data = <IN>;
	}
	return $data;
	    
    } else {
	$self->warn("$path not found");
	return undef;
    }
}


sub _write_file {
    my ($self, $type, $name, $data) = @_;
    
    unless ( -d $self->{_path} ) {
	$self->warn("creating directory $self->{_path}");
	system ("mkdir -p $self->{_path}");
    }

    my $dir = $self->{_path} . '/' . $type . '/';
    unless ( -d $dir ) {
	$self->warn("creating directory $dir...");
	mkdir $dir;
    }

    my $path = $dir . $name;
    if ( -f $path ) {
	return undef;
    }
    
    unless (open OUT, ">$path") {
	warn "couldn't open $path for writing: $!";
	return undef;
    }
    
    print OUT $data;
    close OUT;
}


=head2 _check_file 

Private routine to check for a key or cert file's existence and
non-zero length.

=cut
   
=head2 _write_file

Private routine to write the provided data out to a local file. 

=cut

1;
