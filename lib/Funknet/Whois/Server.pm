package Funknet::Whois::Server;
use strict;
use Net::TCP::Server;
use Data::Dumper;

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

sub new {
    my ($class, $source, $verbose) = @_;
    my $self = bless {}, $class;
    
    unless (defined $source) {
	warn "need a source";
	return undef;
    }

    $self->{_verbose} = $verbose;
    $self->{_source} = $source;
    $self->{_objects} = {};
    
    return $self;
}

sub load {
    my ($self, $file) = @_;
    
    open DATA, "$file"
      or die "can't open $file: $!";
    
    my $currobj;
    while (my $line = <DATA>) {
	chomp $line;

	next if $line =~ /^#/;

	if ($line =~ /^(.*):\s(.*)$/) {
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

		if ($key eq 'origin') {
		    $currobj->{origin} = $value;
		}
	    }
	    
	} else {

	    $self->{_objects}->{$currobj->{type}}->{$currobj->{name}} = $currobj->{text};

	    if ($currobj->{type} eq 'route') {
		push @{ $self->{_index}->{origin}->{$currobj->{origin}} }, $currobj->{text};
	    }

	    undef $currobj;

	}
    }
    close DATA;

    my $num = scalar keys %{ $self->{_objects} };
    return $num;
}

sub go {
    my ($self, $address, $port) = @_;
    my $lh;
    
    if (defined($address))
    {
	$lh = Net::TCP::Server->new($address, $port) 
	  or die "can't bind tcp/$port: $!";
    } else {
	$lh = Net::TCP::Server->new($port) 
	  or die "can't bind tcp/$port: $!";
    }
    
    while (my $sh = $lh->accept) {
        defined (my $pid = fork) or die "fork: $!\n";
	
        if ($pid) {
	    # parent
	    $sh->stopio;
            next;
        }
	
	# child
        $lh->stopio;

      QUERY:
	my $query = <$sh>;
	unless (defined $query) {
	    exit;
	}

	# banner
	print $sh "% This is a FUNKNET Whois Server\n";
	print $sh "% See http://www.funknet.org for details\n\n";

	# remove network line-ending
	$query =~ s/\n//g;
	$query =~ s/\r//g;
	
	# sanitize query
	if ($query =~ /^([A-Za-z0-9-. ]+)$/) {
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
	$query =~ s/ //g;

	#print STDERR Dumper { opts => $opts, query => $query };

	# attempt to answer query
	if (defined $opts->{type} && defined $self->{_objects}->{$opts->{type}}->{$query}) {

	    print $sh $self->{_objects}->{$opts->{type}}->{$query};
	    print $sh "\n\n";
	    $self->_log("object found by name\n");
	    
	} elsif (defined $opts->{inverse} && $opts->{inverse} eq 'origin' && defined $self->{_index}->{origin}->{$query}) {
	    
	    for my $object (@{ $self->{_index}->{origin}->{$query} }) {
		print $sh $object, "\n\n";
		$self->_log("object found via inverse lookup\n");
	    }
	    
	} else {

	    print $sh "% No entries found in the selected source\n\n";
	    $self->_log("*** no object found ***\n");
	}

	# hacktastic. must clean this up. 
	if ($opts->{k} && $query) {
	    goto QUERY;
	}
	
        exit;
    }
}

sub _log {
    my ($self, $msg) = @_;
    if ($self->{_verbose}) {
	print STDERR "whoisd: $msg";
    }
}

1;
