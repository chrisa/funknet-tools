package Funknet::Config::Interactive;
use strict;
use Term::Interact;
use Funknet::Config::Validate qw/ is_ipv4 /;

sub new {
    my ($class,%args) = @_;
    my $self = bless {}, $class;
    return $self;
}

sub get_config {
    my ($self) = @_;
    my $ti = Term::Interact->new();
    
    my $config;

    $config->{local_as} = $ti->get(
				   msg        =>  'Enter your local AS number as \'ASxxxxx\'',
				   check      =>  [
						   qr/^AS\d{1,5}$/,
						   '%s is not in the format ASxxxxx'
						   ],
				   );
    
    $config->{local_os} = $ti->get(
				   msg        =>  'Enter your OS (ios|bsd|linux|solaris)',
				   check      =>  [
						   qr/^(ios|bsd|linux|solaris)$/,
						   '%s is not one of ios|bsd|linux|solaris'
						   ],
				   );
    
    $config->{local_router} = $ti->get(
				       msg        =>  'Enter your router (ios|zebra)',
				       check      =>  [
						       qr/^(ios|zebra)$/,
						       '%s is not one of ios|zebra'
						       ],
				       );
    
    $config->{local_host} = $ti->get(
				     msg        =>  'Enter your host address (IPv4 dotted decimal)',
				     check      =>  [
						     sub{ is_ipv4(shift) },
						     '%s is not a valid IPv4 address'
						     ],
				     );
    
    $config->{local_endpoint} = $ti->get(
					 msg        =>  'Enter your endpoint address (IPv4 dotted decimal)',
					 check      =>  [
							 sub{ is_ipv4(shift) },
							 '%s is not a valid IPv4 address'
							 ],
					 );

    my $rtconfig_default = `which RtConfig`; chomp $rtconfig_default;
    $config->{rtconfig_path} = $ti->get(
					msg        =>  "Enter the path to RtConfig (default $rtconfig_default)",
					default    =>  $rtconfig_default,
					check      =>  [
							sub{ shift; /RtConfig$/ && -x },
							'%s is not a valid path to an RtConfig binary'
							],
					);
    return $config;
}

1;
