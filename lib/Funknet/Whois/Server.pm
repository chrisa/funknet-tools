package Funknet::Whois::Server;
use strict;
use Net::TCP::Server;

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
    my ($class, $source) = @_;
    my $self = bless {}, $class;
    
    unless (defined $source) {
	warn "need a source";
	return undef;
    }

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

		if ($key eq 'origin') {
		    $currobj->{origin} = $value;
		}
	    }
	    
	} else {

	    $self->{_objects}->{$currobj->{name}} = $currobj->{text};

	    if ($currobj->{type} eq 'route') {
		push @{ $self->{_index}->{origin}->{$currobj->{origin}} }, $currobj->{text};
	    }

	    undef $currobj;

	}
    }
    my $num = scalar keys %{ $self->{_objects} };
    return $num;
}

sub go {
    my ($self) = @_;
    my $port = 4343;
    
    my $lh = Net::TCP::Server->new($port) 
      or die "can't bind tcp/$port: $!";
    
    while (my $sh = $lh->accept) {
        defined (my $pid = fork) or die "fork: $!\n";
	
        if ($pid) {
	    # parent
	    $sh->stopio;
            next;
        }
	
	# child
        $lh->stopio;

	# banner
	print $sh "% This is a FUNKNET Whois Server\n";
	print $sh "% See http://www.funknet.org for details\n\n";

	my $query = <$sh>;
	unless (defined $query) {
	    exit;
	}

	# remove network line-ending
	chop $query;
	chop $query;
	
	# sanitize query
	if ($query =~ /^([A-Za-z0-9- ]+)$/) {
	    $query = $1;
	} else {
	    warn "evil query";
	    exit;
	}

	if (defined $self->{_objects}->{$query}) {

	    print $sh $self->{_objects}->{$query};
	    print $sh "\n";
	    
	} elsif ($query =~ s/^-i origin // && defined $self->{_index}->{origin}->{$query}) {
	    
	    for my $object (@{ $self->{_index}->{origin}->{$query} }) {
		print $sh $object, "\n";
	    }
	    
	} else {

	    print $sh "% No entries found in the selected source\n\n";

	}
	
        exit;
    }
}

1;
