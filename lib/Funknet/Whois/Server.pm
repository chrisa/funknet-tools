package Funknet::Whois::Server;
use strict;
use Net::TCP::Server;
use Data::Dumper;
use Funknet::Config::Util qw/ dq_to_int /;

=head1 NAME

Funknet::Whois::Server

=head1 DESCRIPTION

Implements a really, really, simple whoisd. Loads objects from a flat
text file into memory, then runs a forking server. Nothing more. 

=head1 SYNOPSIS

  use Funknet::Whois::Server;

  my $s = new Funknet::Whois::Server("FUNKNET");
  my $num = $s->load("objects");
  $s->go;

=head1 NOTES

Yeah, yeah, it sets SIGCHLD to SIG_IGN. WorksForMe(tm).

=cut

$SIG{CHLD} = 'IGNORE';

use vars qw/ $reload /;
$reload = 0;

sub new {
    my ($class, $source, $file, $verbose) = @_;
    my $self = bless {}, $class;
    
    unless (defined $source) {
	warn "need a source";
	return undef;
    }

    $self->{_file}    = $file;
    $self->{_verbose} = $verbose;
    $self->{_source}  = $source;
    $self->{_objects} = {};
    
    return $self;
}

sub load {
    my ($self) = @_;
    
    open DATA, $self->{_file}
      or die "can't open $self->{_file}: $!";
    
    $self->{_objects} = {};
    $self->{_types}   = {};
    $self->{_index}   = {};
    
    my $currobj;
    my $num;

    my $objects_text;
    while (my $line = <DATA>) {
        next if $line =~ /^#/;
        $objects_text .= $line;
    }

  OBJECT:
    for my $text (split /\r?\n\r?\n/, $objects_text) {
	if (my $object = Funknet::Whois::Object->new($text)) {
            next OBJECT unless $object->source eq $self->{_source};
            
            # store the object under its name
	    $self->{_objects}->{$object->object_type}->{$object->object_name} = scalar $object->text;
	    $num++;
            
            # index on origin for route object inverses
	    if ($object->object_type eq 'route') {
		push @{ $self->{_index}->{origin}->{$object->origin} }, scalar $object->text;
	    }

            # index nic-handle for persons
	    if ($object->object_type eq 'person') {
		$self->{_objects}->{person}->{$object->nic_hdl} = scalar $object->text;
	    }

            # track types for wildcard-type search.
            $self->{_types}->{$object->object_type}++;
	}
    }
    close DATA;

    for my $type (keys %{ $self->{_objects} }) {
        for my $name (keys %{ $self->{_objects}->{$type} }) {
	    $self->_log("$type: $name\n");
	}
    }
    $self->_log("loaded $num objects from $self->{_file}\n");

    return $num;
}

sub start {
    my ($self, $address, $port) = @_;
    
    if (defined($address))
    {
	$self->{_lh} = Net::TCP::Server->new($address, $port) 
	  or die "can't bind tcp/$port: $!";
    } else {
	$self->{_lh} = Net::TCP::Server->new($port) 
	  or die "can't bind tcp/$port: $!";
    }
}

sub go {
    my ($self) = @_;

    # are we supposed to be reloading?
    if ($reload) {
	my $num = $self->load();
	$self->_log("reloaded $num objects\n");
	$reload = 0;
    }
    
    while (my $sh = $self->{_lh}->accept) {
        defined (my $pid = fork) or die "fork: $!\n";
	
        if ($pid) {
	    # parent
	    $sh->stopio;
            next;
        }
	
	# child
        $self->{_lh}->stopio;

      QUERY:

	# banner
	print $sh "% This is a FUNKNET Whois Server\n";
	print $sh "% See http://www.funknet.org for details\n\n";

	my $query = <$sh>;
	unless (defined $query) {
	    exit;
	}

	# remove network line-ending
	$query =~ s/\n//g;
	$query =~ s/\r//g;
	
	# sanitize query
	if ($query =~ /^([A-Za-z0-9-,=. ]+)$/) {
	    $query = " $1"; # space so we can see it's an option, below... 
	    $self->_log("query: $query\n");
	} else {
	    $self->_log("evil query: $query\n");
	    exit;
	}

	# parse options from query:
	my $opts;
		
	# client version 
	if ($query =~ s/ -v ?([^ ]+)//i) {
	    $opts->{client_version} = $1;
	}

	# source
	if ($query =~ s/ -s ?([^ ]+)//i) {
	    $opts->{source} = $1;
	}

	# object type
	if ($query =~ s/ -t ?([^ ]+)//i) {
	    $opts->{type} = $1;
	}
	
	# inverse, origin
	if ($query =~ s/ -i ?([^ ]+)//i) {
	    $opts->{inverse} = $1;
	}

	# persistent connection?
	if ($query =~ s/ -k//) {
	    $opts->{k} = 1;
	}

	# can't remember what these are.
	if ($query =~ s/ -K//) {
	    $opts->{K} = 1;
	}
	if ($query =~ s/ -r//i) {
	    $opts->{r} = 1;
	}

	# trim query of spaces, now it has no options
	# all spaces? or just at start/end?
	$query =~ s/^ //g;
	$query =~ s/ $//g;

	# attempt to answer query

        my $count = 0;
	if (defined $opts->{inverse} && $opts->{inverse} eq 'origin' && defined $self->{_index}->{origin}->{$query}) {
	    
	    for my $object (sort { dq_to_int(_route($a)) <=> dq_to_int(_route($b)) } 
	                        @{ $self->{_index}->{origin}->{$query} }) {
		print $sh $object, "\n";
		$self->_log("object found via inverse lookup\n");
	    }
	    print $sh "\n";
            $count++;
            
        } elsif (defined $opts->{type} && defined $self->{_objects}->{$opts->{type}}->{$query}) {

	    print $sh $self->{_objects}->{$opts->{type}}->{$query};
	    print $sh "\n\n";
	    $self->_log("object found by name\n");
            $count++;

	} elsif (!defined $opts->{type}) {

            for my $type (keys %{ $self->{_types} }) {

                if (defined $self->{_objects}->{$type}->{$query}) {
                    
                    print $sh $self->{_objects}->{$type}->{$query};
                    print $sh "\n\n";
                    $self->_log("object found by name with wildcard type\n");
                    $count++;
                }
            }

        } else {
            
            # nothing?
	}

        unless ($count) {

            print $sh "% No entries found in the selected source\n\n\n";
            $self->_log("*** no object found ***\n");

        }

	# hacktastic. must clean this up. 
	if ($opts->{k} && $query) {
	    goto QUERY;
	}
	
        exit;
    }
    if ($!{EINTR}) {
	$self->go();
    }
}

sub _log {
    my ($self, $msg) = @_;
    if ($self->{_verbose}) {
	print STDERR "whoisd: $msg";
    }
}

sub _route {
    my ($route) = @_;
    my ($dq) = $route =~ /route:\s+(\d+\.\d+\.\d+\.\d+)/;
    return $dq;
}

1;
