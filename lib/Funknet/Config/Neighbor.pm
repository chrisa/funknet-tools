package Funknet::Config::Neighbor;
use strict;
use Funknet::Config::Validate qw/ is_ipv4 /;

# limitation - we don't deal with multiprotocol BGP yet.

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'host')) {
	warn "missing source";
	return undef;
    } else {
	$self->{_source} = $args{source};
    }

    unless (defined $args{remote_as}) {
	warn "missing remote_as";
	return undef;
    } else {
	my $asno = $args{remote_as};
	$asno =~ s/^AS//;
	$self->{_remote_as} = $asno;
    }

    unless (defined $args{remote_addr}) {
	warn "missing remote_addr";
	return undef;
    } else {
	$self->{_remote_addr} = $args{remote_addr};
    }

    if (defined $args{description}) {
	$self->{_description} = $args{description};
    }

    if (defined $args{acl_in}) {
	$self->{_acl_in} = $args{acl_in};
    }
    if (defined $args{acl_out}) {
	$self->{_acl_out} = $args{acl_out};
    }

    return $self;
}

sub config {
    my ($self) = @_;

    my $config = "neighbor $self->{_remote_addr} remote-as $self->{_remote_as}\n";
    if (defined $self->{_description}) {
        $config .= "neighbor $self->{_remote_addr} description $self->{_description}\n";
    }
    if (defined $self->{_acl_in}) {
	$config .= "neighbor $self->{_remote_addr} route-map ".($self->{_acl_in}->name)." in\n";
    }
    if (defined $self->{_acl_out}) {
	$config .= "neighbor $self->{_remote_addr} route-map ".($self->{_acl_out}->name)." out\n";
    }
    return $config;
}

sub diff {
    my ($whois, $host) = @_;
    my @cmds;

    unless ($whois->remote_as == $host->remote_as) {
	# change of as - delete, restart from scratch.
	push @cmds, "no neighbor ".$host->remote_addr;
	push @cmds, $whois->config;
    }

    unless ($whois->description eq $host->description) {
	push @cmds, "neighbor ".$whois->remote_addr." description ".$whois->description;
    }
    
    if (defined $whois->{_acl_in}) {
	if (defined $host->{_acl_in}) {
	    # both exist, check they're the same
	    unless ($whois->{_acl_in}->name eq $host->{_acl_in}->name) {
		push @cmds, "neighbor ".$whois->remote_addr." route-map ".$whois->{_acl_in}->name." in";
	    }
	} else {
	    # nothing in host, but whois exists: add.
	    push @cmds, "neighbor ".$whois->remote_addr." route-map ".$whois->{_acl_in}->name." in";
	}
    } else {
	if (defined $host->{_acl_in}) {
	    # host has acl, but it's not in whois: delete
	    push @cmds, "no neighbor ".$host->remote_addr." route-map ".$host->{_acl_in}->name." in";
	}
    }
    
    if (defined $whois->{_acl_out}) {
	if (defined $host->{_acl_out}) {
	    # both exist, check they're the same
	    unless ($whois->{_acl_out}->name eq $host->{_acl_out}->name) {
		push @cmds, "neighbor ".$whois->remote_addr." route-map ".$whois->{_acl_out}->name." out";
	    }
	} else {
	    # nothing in host, but whois exists: add.
	    push @cmds, "neighbor ".$whois->remote_addr." route-map ".$whois->{_acl_out}->name." out";
	}
    } else {
	if (defined $host->{_acl_out}) {
	    # host has acl, but it's not in whois: delete
	    push @cmds, "no neighbor ".$host->remote_addr." route-map ".$host->{_acl_out}->name." out";
	}
    }

    return @cmds;
}

# accessors

sub remote_addr {
    my ($self) = @_;
    return $self->{_remote_addr};
}
sub remote_as {
    my ($self) = @_;
    return $self->{_remote_as};
}
sub description {
    my ($self) = @_;
    return $self->{_description};
}

1;
