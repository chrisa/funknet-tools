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

    my $config = " neighbor $self->{_remote_addr} remote-as $self->{_remote_as}\n";
    if (defined $self->{_description}) {
        $config .= " neighbor $self->{_remote_addr} description $self->{_description}\n";
    }
    if (defined $self->{_acl_in}) {
	$config .= " neighbor $self->{_remote_addr} route-map ".($self->{_acl_in}->name)." in\n";
    }
    if (defined $self->{_acl_out}) {
	$config .= " neighbor $self->{_remote_addr} route-map ".($self->{_acl_out}->name)." out\n";
    }
    return $config;
}

1;
