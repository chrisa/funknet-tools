package Funknet::Config::AccessList::Zebra;
use strict;
use Net::Telnet;

sub _get_host {
    my ($self, %args) = @_;
    
    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[\>\#] $/',
			      Port    => 2605,
			    );
    
    $t->open($self->{_local_host});
    $t->cmd($self->{_password});
    $t->cmd('terminal length 0');

    my @output = $t->cmd("show ip bgp neighbor $args{remote_addr}");
    
    my ($acl_in, $acl_out);
    foreach my $line (@output) {
	if ($line =~ /Route map for incoming advertisements is (.+)/) {
	    $acl_in = $1;
	}
	if ($line =~ /Route map for outgoing advertisements is (.+)/) {
	    $acl_out = $1;
	}
    }

    if ($args{dir} eq 'import') {
	@output = $t->cmd("sho ip prefix-list $acl_in");
	$self->{_name} = $acl_in;
	$self->{_acl_text} = join "\n",@output;
    }
    if ($args{dir} eq 'export') {
	@output = $t->cmd("sho ip prefix-list $acl_out");
	$self->{_name} = $acl_out;
	$self->{_acl_text} = join "\n",@output;
    }

}

1;
