package Funknet::Config::CommandSet;
use strict;
use Funknet::Config::CLI;
use Funknet::Config::Root;

=head1 NAME

Funknet::Config::CommandSet

=head1 DESCRIPTION

A pair of classes to hold lists of commands, and a generic
constructor. Class ::CommandSet::Host has an apply method which
executes the commands as root on the local system. Class
::CommandSet::CLI has an apply method which uses the CLI modules to
execute commands on Zebra or IOS routers. Both will return their
command lists with a text representation of where they should be
executed, for preview and warnings. 

=head1 CONSTRUCTOR

Pass in the list of commands and the target. Also pass the static
local_* values relevant. XXX -- this should come from ConfigFile.

=head1 as_text

Returns the list of commands, with a line describing where they should
be executed. For notifying proposed changes.

=head1 apply

Runs the list of commands. XXX -- needs to gain root properly, not
expect to be run as root.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = {};

    $self->{_cmds} = $args{cmds};
    if (defined $args{target} && $args{target} eq 'cli') {
	bless $self, 'Funknet::Config::CommandSet::CLI';
	return $self;
    }
    if (defined $args{target} && $args{target} eq 'host') {
	bless $self, 'Funknet::Config::CommandSet::Host';
 	return $self;
    }
    return undef;
}

sub cmds {
    my ($self) = @_;
    return @{ $self->{_cmds} };
}

package Funknet::Config::CommandSet::CLI;
use base qw/ Funknet::Config::CommandSet /;

sub as_text {
    my ($self) = @_;
    my $l = Funknet::Config::ConfigFile->local;
    if (scalar @{ $self->{_cmds} }) {
	my $text = "in enable mode on $l->{host}\n";
	$text .= join "\n", @{ $self->{_cmds} };
	return $text;
    } else {
	return '';
    }
}

sub apply {
    my ($self) = @_;

    # hand off to CLI module to get these commands executed in enable mode
   
    my $cli = Funknet::Config::CLI->new();
    
    my $rv = $cli->exec_enable( $self );
    return $rv;
}

package Funknet::Config::CommandSet::Host;
use base qw/ Funknet::Config::CommandSet /;

sub as_text {
    my ($self) = @_;
    if (scalar @{ $self->{_cmds} }) {
	my $text = "as root on localhost:\n";
	$text .= join "\n", @{ $self->{_cmds} };
	return $text;
    } else {
	return '';
    }
}

sub apply {
    my ($self) = @_;

# New interface to Root.pm, not quite ready yet.

#    my $root = Funknet::Config::Root->new;
#    unless ($root) {
#	die "can't get root";
#    }
#    my $rv = $root->exec_root( $self );
#    return $rv;

    if (scalar @{ $self->{_cmds} }) {
        my $text = join "\n", @{ $self->{_cmds} };
	qx[$text
];
        return $text;
    } else {
        return '';
    }
}

1;
