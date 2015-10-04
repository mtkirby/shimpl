#!/usr/bin/perl
# 20151003 Kirby

# LICENSE
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

use Net::Netmask;
use strict;
use Getopt::Long;
use Carp;
use diagnostics;
use Net::Subnet;

# TODO create persistent config files in /etc/shim
# TODO move scripts to /bin
# TODO option add iptables to existing shims

my @a;
my $a;
my $b;
my @cmdout;
my %dhcp;
my @foundrouters;
my $foundrouters;
my @getrouters;
my @getshimips;
my $guesscidr;
my $help;
my $ip;
my $lockfile = '/tmp/shim.lock';
my %my;
my $netinfo;
my $pid = $$;
my %rdrport;
my %router;
my %shim;
my @shimips;
my $showshims;
my $unshim;
my $unshimall;
my $val;
my $var;

$shim{'if'}   = 'tap1';
$router{'if'} = 'tap1';

GetOptions(
	"extif=s"          => \$my{'extif'},
	"intif=s"          => \$my{'intif'},
	"routermac=s"      => \$router{'mac'},
	"routerip=s"       => \$router{'ip'},
	"shimmac=s"        => \$shim{'mac'},
	"shimip=s"         => \$shim{'ip'},
	"shimcidr=s"       => \$shim{'cidr'},
	"guesscidr"        => \$guesscidr,
	"shimhostname=s"   => \$shim{'hostname'},
	"shimdomainname=s" => \$shim{'domainname'},
	"vlan=s"           => \$my{'vlan'},
	"shimdns=s"        => \$shim{'dns'},
	"shimntp=s"        => \$shim{'ntp'},
	"carveports=s"     => \$my{'carveports'},
	"rdrports=s"       => \$my{'rdrports'},
	"showshims"        => \$showshims,
	"unshimall"        => \$unshimall,
	"unshim=s"         => \$unshim,
	"help"             => \$help,
);

if ($help) {
	&printhelp();
	exit 0;
}

if ($showshims) {
	&showshims();
	exit 0;
}

if ($unshimall) {
	&unshimall();
	exit 0;
}

if ($unshim) {
	&unshim($unshim);
	exit 0;
}

##################################################
# Check for apps, namespace support, and modules
if ( $> != 0 ) {
    croak "you must run as root";
} else {
    umask(0700);
}

`which dhclient >/dev/null 2>&1`;
if ( $? != 0 ) {
	croak "you need to install dhclient";
}

`which dhcpd >/dev/null 2>&1`;
if ( $? != 0 ) {
	croak "you need to install dhcpd";
}

`which brctl >/dev/null 2>&1`;
if ( $? != 0 ) {
	croak "you need to install brctl (bridge utilities)";
}

`ip netns add DELME-$pid >/dev/null 2>&1`;
if ( $? != 0 ) {
	croak "your kernel does not support namespaces";
} else {
	`ip netns del DELME-$pid >/dev/null 2>&1`;
}

unless ( $my{'extif'} ) {
	$my{'extif'} = 'eth0';
}
`ip link show $my{'extif'}`;
if ( $? != 0 ) {
	croak "You do not have an $my{'extif'}";
}

unless ( $my{'intif'} ) {
	$my{'intif'} = 'eth1';
}
`ip link show $my{'intif'}`;
if ( $? != 0 ) {
	croak "You do not have an $my{'intif'}";
}

&runcmd( 1, "modprobe br_netfilter" );
&runcmd( 1, "modprobe arptable_filter" );

##################################################

##################################################
# check parameters
if ( $shim{'mac'} !~ m/^([0-9a-f]{2}(:|$)){6}$/i ) {
	croak "bad shimmac $shim{'mac'}";
}

if ( ( $shim{'ip'} ) and ( $shim{'ip'} !~ m/\d+\.\d+\.\d+\.\d+/ ) ) {
	croak "bad shimip $shim{'ip'}";
}
if ( ( $router{'mac'} ) and ( $router{'mac'} !~ m/^([0-9a-f]{2}(:|$)){6}$/i ) ) {
	croak "bad routermac $router{'mac'}";
}

if ( ( $router{'ip'} ) and ( $router{'ip'} !~ m/\d+\.\d+\.\d+\.\d+/ ) ) {
	croak "bad routerip $router{'ip'}";
}

if ( ( $shim{'cidr'} ) and ( $shim{'cidr'} !~ m/^\d+$/ ) ) {
	croak "bad shimcidr $shim{'cidr'}";
}
if ( $shim{'cidr'} ) {
	$netinfo = new Net::Netmask("1.1.1.1/$shim{'cidr'}");
	$shim{'subnetmask'} = $netinfo->mask();
}

if ( $shim{'dns'} ) {
	@{ $shim{'a_dns'} } = split( /,/, $shim{'dns'} );
	foreach ( @{ $shim{'a_dns'} } ) {
		if ( $_ !~ m/^\d+\.\d+\.\d+\.\d+$/ ) {
			croak "bad shimdns $_";
		}
	}
}

if ( $shim{'ntp'} ) {
	@{ $shim{'a_ntp'} } = split( /,/, $shim{'ntp'} );
	foreach ( @{ $shim{'a_ntp'} } ) {
		if ( $_ !~ m/^\d+\.\d+\.\d+\.\d+$/ ) {
			croak "bad shimntp $_";
		}
	}
}

if ( $shim{'ip'} ) {
	$dhcp{'dodhcp'} = 0;
	if ( !$router{'ip'} ) {
		croak "must defined routerip if shimip is specified (dhcp disabled)";
	}
	if ( !$shim{'cidr'} ) {
		$guesscidr = 1;
	}
} else {
	$dhcp{'dodhcp'} = 1;
}

if ($guesscidr) {
	$shim{'cidr'} = &guesscidr( $shim{'ip'}, $router{'ip'} );
}

if ( ( $my{'vlan'} ) and ( $my{'vlan'} !~ m/^\d+$/ ) ) {
	croak "bad vlan id $my{'vlan'}";
}

if ( $my{'carveports'} ) {
	$my{'carveports'} =~ s/-/:/g;
	$my{'carveports'} =~ s/\s+//g;
	if ( $_ !~ m/\d+/ ) {
		croak "bad carveports";
	}
}

if ( $my{'rdrports'} ) {
	$my{'rdrports'} =~ s/\s+//g;
	foreach ( split( /,/, $my{'rdrports'} ) ) {
		if ( $_ !~ m/\d+-\d+/ ) {
			croak "bad rdrports $my{'rdrports'}";
		} else {
			( $a, $b ) = split( /-/, $_ );
			$rdrport{$a} = $b;
		}
	}
}

##################################################

$shim{'ns'} = 'S' . $shim{'mac'};
$shim{'ns'} =~ s/://g;
if ( $router{'mac'} ) {
	$router{'ns'} = 'R' . $router{'mac'};
	$router{'ns'} =~ s/://g;
}

`ip netns exec $shim{'ns'} ip link list >/dev/null 2>&1`;
if ( $? == 0 ) {
	croak "A shimns already exists for $shim{'mac'}";
}

#####
# pre-flight check
foreach ( 'br0', 'br1' ) {
	@cmdout = `brctl show $_ 2>&1`;
	next unless ( grep( /No such device/, @cmdout ) );
	&runcmd( 1, "brctl addbr $_" );
	if ( $_ eq 'br0' ) {
		&runcmd( 1, "brctl addif $_ $my{'extif'}" );
	} elsif ( $_ eq 'br1' ) {
		&runcmd( 1, "brctl addif $_ $my{'intif'}" );
	}
	&runcmd( 1, "brctl stp $_ off" );
	&runcmd( 1, "ip link set dev $_ up" );
}

@cmdout = `brctl show tap0 2>&1`;
if ( grep( /No such device/, @cmdout ) ) {
	&runcmd( 1, "ip link add tap0 type bridge" );
	&runcmd( 1, "ip link set dev tap0 up" );
	&runcmd( 1, "ip address add dev tap0 169.254.0.1/16" );
}

&runcmd( 1, "sysctl -w net.ipv4.conf.all.forwarding=1" );

@cmdout = `systemctl is-active NetworkManager 2>&1`;
if ( grep( /active/, @cmdout ) ) {
	&runcmd( 0, "systemctl stop NetworkManager" );
}
#####

#
# HERE IS WHERE WE START WORKING
#

# reserve brips so we can run parallel shims
while ( -f "$lockfile" ) {
	sleep(1);
}
`touch "$lockfile"`;
$shim{'brip'} = &getnextip();
&runcmd( 1, "ip address add dev tap0 ${shim{'brip'}}/16" );
$router{'brip'} = &getnextip();
&runcmd( 1, "ip address add dev tap0 $router{'brip'}/16" );
unlink("$lockfile");

# Your choice.  Safe to fork here.
#fork && exit;

#
# build shim ns
#
&runcmd( 1, "ip netns add $shim{'ns'}" );

# use temporary tap name to avoid collisions when executing shims in parallel
# we will use the pid to make sure
# Not sure why br returns 1 when it works fine on ln.  Seems to work nonetheless
$shim{'nsbr'} = 'br' . $shim{'ns'};
$shim{'nsln'} = 'ln' . $shim{'ns'};
&runcmd( 0, "ip link add tap1-$pid type veth peer name $shim{'nsbr'}" );
&runcmd( 1, "brctl addif br0 $shim{'nsbr'}" );
&runcmd( 1, "ip link set tap1-$pid netns $shim{'ns'}" );
&runcmd( 1, "ip link set dev $shim{'nsbr'} up" );
&runcmd( 1, "ip netns exec $shim{'ns'} ip link set dev tap1-$pid name $shim{'if'}" );
&runcmd( 1, "ip netns exec $shim{'ns'} ip link set dev $shim{'if'} up" );
&runcmd( 1, "ip netns exec $shim{'ns'} ip link set dev $shim{'if'} address $shim{'mac'}" );

if ( $my{'vlan'} ) {
	&runcmd( 1, "ip link add link $shim{'if'} name $shim{'if'} type vlan id $my{'vlan'}" );
	$shim{'if'} .= ".$my{'vlan'}";
	&runcmd( 1, "ip link set $shim{'if'} netns $shim{'ns'}" );
	&runcmd( 1, "ip netns exec $shim{'ns'} ip link set dev $shim{'if'} address $shim{'mac'}" );
}

if ( $dhcp{'dodhcp'} == 1 ) {
	open( FD, '>', "/tmp/dhclient-${shim{'ns'}}.conf" ) or croak "unable to write to /tmp/dhclient-${shim{'ns'}}.conf";
	print FD qq(option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n);
	if ( $shim{'hostname'} ) {
		print FD qq(send host-name = $shim{'hostname'};\n);
	}
	print FD qq(request subnet-mask, broadcast-address, routers, domain-name, domain-name-servers, domain-search, host-name, netbios-name-servers, netbios-scope, netbios-dd-server, netbios-node-type, ntp-servers, rfc3442-classless-static-routes;\n);
	close(FD);

	$dhcp{'success'} = 0;
	while ( $dhcp{'success'} == 0 ) {
		print qq(Running dhclient\n);
		print qq(Running ip netns exec $shim{'ns'} dhclient -sf /root/shim-dhclient-script -cf /tmp/dhclient-${shim{'ns'}}.conf $shim{'if'}\n);

		# shim-dhclient-script is modified to output 'set' and we will grab the vals below
		@a = `ip netns exec $shim{'ns'} dhclient -sf /root/shim-dhclient-script -cf /tmp/dhclient-${shim{'ns'}}.conf $shim{'if'}`;
		if ( grep( /new_ip_address/, @a ) ) {
			$dhcp{'success'} = 1;
		}
	}
	foreach (@a) {
		chomp;
		$_ =~ s/["']//g;
		next unless ( $_ =~ m/=/ );
		( $var, $val ) = split( /=/, $_ );

		# shortcut. make everything an array.  dhcp can be unpredictable
		@{ $dhcp{$var} } = split( /\s+/, $val );
	}

	if ( $dhcp{'new_ip_address'} ) {
		$shim{'ip'} = $dhcp{'new_ip_address'}[0];
	} else {
		croak "unable to get IP from dhcp";
	}

	if ( $dhcp{'new_subnet_mask'} ) {
		$netinfo         = new Net::Netmask("$shim{'ip'}/$dhcp{'new_subnet_mask'}[0]");
		$shim{'netmask'} = $dhcp{'new_subnet_mask'}[0];
		$shim{'cidr'}    = $netinfo->bits();
	} else {
		croak "unable to get CIDR from dhcp";
	}
} else {
	&runcmd( 1, "ip netns exec $shim{'ns'} ip addr add dev $shim{'if'} $shim{'ip'}/$shim{'cidr'}" );
}

if ( $router{'ip'} ) {
	&runcmd( 1, "ip netns exec $shim{'ns'} ip route add default via $router{'ip'}" );
} else {
	$router{'ip'} = $dhcp{'new_routers'}[0];
    if ( $router{'ip'} !~ m/\d+\.\d+\.\d+\.\d+/ ) {
    	croak "invalid routerip from dhcp: $router{'ip'}";
    }
}
if ( !$router{'mac'} ) {
	&runcmd( 1, "ip netns exec $shim{'ns'} arping -r -i $shim{'if'} -C1 $router{'ip'}" );
	$router{'mac'} = `ip netns exec $shim{'ns'} arping -r -i $shim{'if'} -C1 $router{'ip'}`;
	chomp $router{'mac'};
    if ( $router{'mac'} !~ m/^([0-9a-f]{2}(:|$)){6}$/i ) {
	    croak "invlaid routermac: $router{'mac'}\n";
    }
} else {
	&runcmd( 1, "ip netns exec $shim{'ns'} arp -i $shim{'if'} -s $router{'ip'} $router{'mac'}" );
}
$router{'ns'} = 'R' . $router{'mac'};
$router{'ns'} =~ s/://g;

&runcmd( 1, "ip link add tap2-$pid type veth peer name $shim{'nsln'}" );
&runcmd( 1, "brctl addif tap0 $shim{'nsln'}" );
&runcmd( 1, "ip link set tap2-$pid netns $shim{'ns'}" );
&runcmd( 1, "ip link set dev $shim{'nsln'} up" );
&runcmd( 1, "ip netns exec $shim{'ns'} ip link set dev tap2-$pid name tap2" );
&runcmd( 1, "ip netns exec $shim{'ns'} ip link set dev tap2 up" );
&runcmd( 1, "ip address del dev tap0 $shim{'brip'}/16" );
&runcmd( 1, "ip netns exec $shim{'ns'} ip address add dev tap2 $shim{'brip'}/16" );

`ip netns exec $router{'ns'} ip link list >/dev/null 2>&1`;
if ( $? != 0 ) {
	#
	# build router ns
	#
	$router{'nsbr'} = 'br' . $router{'ns'};
	$router{'nsln'} = 'ln' . $router{'ns'};
	&runcmd( 1, "ip netns add $router{'ns'}" );
	&runcmd( 0, "ip link add tap1-$pid type veth peer name $router{'nsbr'}" );
	&runcmd( 1, "brctl addif br1 $router{'nsbr'}" );
	&runcmd( 1, "ip link set tap1-$pid netns $router{'ns'}" );
	&runcmd( 1, "ip link set dev $router{'nsbr'} up" );
	&runcmd( 1, "ip netns exec $router{'ns'} ip link set dev tap1-$pid name $router{'if'}" );
	&runcmd( 1, "ip netns exec $router{'ns'} ip link set dev $router{'if'} up" );
	&runcmd( 1, "ip netns exec $router{'ns'} ip link set dev $router{'if'} address $router{'mac'}" );

	if ( $my{'vlan'} ) {
		&runcmd( 1, "ip link add link $router{'if'} name $router{'if'} type vlan id $my{'vlan'}" );
		$router{'if'} .= ".$my{'vlan'}";
		&runcmd( 1, "ip link set $router{'if'} netns $router{'ns'}" );
		&runcmd( 1, "ip netns exec $router{'ns'} ip link set dev $router{'if'} address $router{'mac'}" );
	}
	&runcmd( 1, "ip netns exec $router{'ns'} ip address add dev $router{'if'} $router{'ip'}/$shim{'cidr'}" );
	&runcmd( 1, "ip link add tap2-$pid type veth peer name $router{'nsln'}" );
	&runcmd( 1, "brctl addif tap0 $router{'nsln'}" );
	&runcmd( 1, "ip link set dev $router{'nsln'} up" );
	&runcmd( 1, "ip link set tap2-$pid netns $router{'ns'}" );
	&runcmd( 1, "ip netns exec $router{'ns'} ip link set dev tap2-$pid name tap2" );
	&runcmd( 1, "ip netns exec $router{'ns'} ip link set dev tap2 up" );
}
&runcmd( 1, "ip address del dev tap0 $router{'brip'}/16" );
&runcmd( 1, "ip netns exec $router{'ns'} ip address add dev tap2 $router{'brip'}/16" );

$shim{'routetable'} = &getroutetablename("$shim{'ip'}");

# view routes via ip route show table <tablename>
&removeshimroute( "$router{'ns'}", "$shim{'ip'}", "$shim{'routetable'}" );
&runcmd( 0, "ip netns exec $router{'ns'} ip rule del table $shim{'routetable'}" );
&runcmd( 1, "ip netns exec $router{'ns'} ip rule add from $shim{'ip'} lookup $shim{'routetable'}" );
&runcmd( 1, "ip netns exec $router{'ns'} ip route add default via $shim{'brip'} table $shim{'routetable'}" );

if ( $my{'carveports'} ) {
	&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -I PREROUTING -d $shim{'ip'} -p tcp -m tcp -m multiport --dports $my{'carveports'} -j DNAT --to-destination 169.254.0.1" );
	&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -I PREROUTING -d $shim{'ip'} -p udp -m udp -m multiport --dports $my{'carveports'} -j DNAT --to-destination 169.254.0.1" );
	&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p tcp -m tcp -m multiport --dports $my{'carveports'} -j SNAT --to-source $shim{'brip'}" );
	&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p udp -m udp -m multiport --dports $my{'carveports'} -j SNAT --to-source $shim{'brip'}" );

	&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -I PREROUTING -s $shim{'ip'} -d $router{'ip'} -p tcp -m tcp -m multiport --dports $my{'carveports'} -j DNAT --to-destination 169.254.0.1" );
	&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -I PREROUTING -s $shim{'ip'} -d $router{'ip'} -p udp -m udp -m multiport --dports $my{'carveports'} -j DNAT --to-destination 169.254.0.1" );
	&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p tcp -m tcp -m multiport --dports $my{'carveports'} -j SNAT --to-source $router{'brip'}" );
	&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p udp -m udp -m multiport --dports $my{'carveports'} -j SNAT --to-source $router{'brip'}" );
}

if ( $my{'rdrports'} ) {
	foreach ( keys %rdrport ) {
		&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -I PREROUTING -d $shim{'ip'} -p tcp -m tcp --dport $_ -j DNAT --to-destination 169.254.0.1:$rdrport{$_}" );
		&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -I PREROUTING -d $shim{'ip'} -p udp -m udp --dport $_ -j DNAT --to-destination 169.254.0.1:$rdrport{$_}" );
		&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p tcp -m tcp --dport $rdrport{$_} -j SNAT --to-source $shim{'brip'}" );
		&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p udp -m udp --dport $rdrport{$_} -j SNAT --to-source $shim{'brip'}" );

		&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -I PREROUTING -s $shim{'ip'} -p tcp -m tcp --dport $_ -j DNAT --to-destination 169.254.0.1:$rdrport{$_}" );
		&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -I PREROUTING -s $shim{'ip'} -p udp -m udp --dport $_ -j DNAT --to-destination 169.254.0.1:$rdrport{$_}" );
		&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p tcp -m tcp --dport $rdrport{$_} -j SNAT --to-source $router{'brip'}" );
		&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p udp -m udp --dport $rdrport{$_} -j SNAT --to-source $router{'brip'}" );
	}
}

&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -A PREROUTING -d $shim{'ip'} ! -p icmp -j DNAT --to-destination $router{'brip'}" );
&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -A PREROUTING -d $shim{'brip'} ! -p icmp -j DNAT --to-destination $router{'ip'}" );
&runcmd( 1, "ip netns exec $shim{'ns'} iptables -t nat -A POSTROUTING -o $shim{'if'} ! -d 169.254.0.0/16 -j SNAT --to $shim{'ip'}" );

&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -A PREROUTING -d $router{'ip'} ! -p icmp -j DNAT --to-destination $shim{'brip'}" );
&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -A PREROUTING -d $router{'brip'} ! -p icmp -j DNAT --to-destination $shim{'ip'}" );
&runcmd( 1, "ip netns exec $router{'ns'} iptables -t nat -A POSTROUTING -s $shim{'ip'} -j SNAT --to $router{'brip'}" );

# hide from traceroutes
&runcmd( 0, "ip netns exec $router{'ns'} iptables -t mangle -D PREROUTING -m ttl --ttl-gt 1  -j TTL --ttl-inc 2" );
&runcmd( 1, "ip netns exec $router{'ns'} iptables -t mangle -A PREROUTING -m ttl --ttl-gt 1  -j TTL --ttl-inc 2" );

# prevent dhcp clients from detecting a duplicate ip
&runcmd( 1, "ip netns exec $router{'ns'} arptables -I INPUT -s $shim{'ip'} -d $shim{'ip'} -j DROP" );

# safeguard
# In the case that someone reverses the cables.
# We don't want the shimbox to answer as the router on the outside interface.
&runcmd( 0, "ip netns exec $router{'ns'} arptables -D INPUT -i $router{'if'} -j DROP" );
&runcmd( 1, "ip netns exec $router{'ns'} arptables -A INPUT -i $router{'if'} -s $shim{'ip'} -j ACCEPT" );
&runcmd( 1, "ip netns exec $router{'ns'} arptables -A INPUT -i $router{'if'} --source-mac $shim{'mac'} -j ACCEPT" );
&runcmd( 1, "ip netns exec $router{'ns'} arptables -A INPUT -i $router{'if'} -j DROP" );

&runcmd( 1, "ip netns exec $shim{'ns'} arptables -A INPUT -i $shim{'if'} -d $shim{'ip'} -j ACCEPT" );
&runcmd( 1, "ip netns exec $shim{'ns'} arptables -A INPUT -i $shim{'if'} --destination-mac $shim{'mac'} -j ACCEPT" );
&runcmd( 1, "ip netns exec $shim{'ns'} arptables -A INPUT -i $shim{'if'} -j DROP" );

&runcmd( 1, "ip netns exec $router{'ns'} arp -s $shim{'ip'} $shim{'mac'}" );

if ( $dhcp{'dodhcp'} == 1 ) {
	unless ( -f "/tmp/shimdhcpd-${router{'ns'}}.conf" ) {
		open( FD, '>', "/tmp/shimdhcpd-${router{'ns'}}.conf" ) or croak "unable to write /tmp/shimdhcpd-${router{'ns'}}.conf";
		print FD qq(ddns-update-style none;\n);
		print FD qq(default-lease-time 36000;\n);
		print FD qq(max-lease-time 72000;\n);
		print FD qq(log-facility local7;\n);
		print FD qq(subnet 0.0.0.0 netmask 0.0.0.0 {\n);
		print FD qq(}\n);
		close(FD);
	}

    @a = '';
	open( FD, '+<', "/tmp/shimdhcpd-${router{'ns'}}.conf" ) or croak "unable to write /tmp/shimdhcpd-${router{'ns'}}.conf";
	flock FD, 2;
	while (<FD>) {
		next if ( $_ =~ m/$shim{'ns'}/ );
		push( @a, $_ );
	}
	seek FD, 0, 0;
	truncate "/tmp/shimdhcpd-${router{'ns'}}.conf", 0;
	print FD @a;
	print FD qq(include "/tmp/shimdhcpd-${shim{'ns'}}.conf";\n);
	close(FD);

	open( FD, '>', "/tmp/shimdhcpd-${shim{'ns'}}.conf" ) or croak "unable to write /tmp/shimdhcpd-${shim{'ns'}}.conf";
	print FD qq(host $shim{'ns'} {\n);
	print FD qq(	hardware ethernet $shim{'mac'};\n);
	print FD qq(	fixed-address $shim{'ip'};\n);
	print FD qq(	option routers $router{'ip'};\n);
	if ( $shim{'hostname'} ) {
		print FD qq(	option host-name "$shim{'hostname'}";\n);
	} elsif ( $dhcp{'new_host_name'} ) {
		print FD qq(	option host-name "${dhcp{'new_host_name'}[0]}";\n);
	}
	if ( $shim{'domainname'} ) {
		print FD qq(	option domain-name "$shim{'domainname'}";\n);
	} elsif ( $dhcp{'new_domain_name'} ) {
		print FD qq(	option domain-name "${dhcp{'new_domain_name'}[0]}";\n);
	}
	if ( $dhcp{'new_subnet_mask'} ) {
		print FD qq(	option subnet-mask ${dhcp{'new_subnet_mask'}[0]};\n);
	}
	if ( $dhcp{'new_domain_name_servers'} ) {
		print FD qq(	option domain-name-servers ) . join( ', ', @{ $dhcp{'new_domain_name_servers'} } ) . qq(;\n);
	}
	if ( $dhcp{'new_ntp_servers'} ) {
		print FD qq(	option ntp-servers ) . join( ', ', @{ $dhcp{'new_ntp_servers'} } ) . qq(;\n);
	}
	if ( $dhcp{'new_netbios_name_servers'} ) {
		print FD qq(	option netbios-name-servers ) . join( ', ', @{ $dhcp{'new_netbios_name_servers'} } ) . qq(;\n);
	}
	if ( $dhcp{'new_netbios_node_type'} ) {
		print FD qq(	option netbios-node-type ${dhcp{'new_netbios_node_type'}[0]};\n);
	}
	if ( $dhcp{'new_domain_search'} ) {

		# so annoying
		foreach ( @{ $dhcp{'new_domain_search'} } ) {
			$_ =~ s/\.$//g;
			push( @{ $dhcp{'my_domain_search'} }, $_ );
		}
		print FD qq(	option domain-search ") . join( ', ', @{ $dhcp{'my_domain_search'} } ) . qq(";\n);
	}
	print FD qq(}\n);
	close(FD);

	$router{'nsdhcppid'} = "/var/run/dhcpd-${router{'ns'}}.pid";
	if ( -f "$router{'nsdhcppid'}" ) {
		open( FD, '<', "$router{'nsdhcppid'}" );
		$dhcp{'pid'} = (<FD>);
		chomp $dhcp{'pid'};
		`kill $dhcp{'pid'}`;
		close(FD);
		unlink "$router{'nsdhcppid'}";
	}
	`touch /var/lib/dhcp/dhcpd-${router{'ns'}}.leases`;
	&runcmd( 1, "ip netns exec $router{'ns'} /usr/sbin/dhcpd -q -lf /var/lib/dhcp/dhcpd-${router{'ns'}}.leases -cf /tmp/shimdhcpd-${router{'ns'}}.conf -pf /var/run/dhcpd-${router{'ns'}}.pid $router{'if'}" );

	if ( -f "/etc/netns/$shim{'ns'}/resolv.conf" ) {
		unlink("/etc/netns/$shim{'ns'}/resolv.conf");
	}
	mkdir( "/etc/netns",             0755 );
	mkdir( "/etc/netns/$shim{'ns'}", 0755 );
	open( FD, '>', "/etc/netns/$shim{'ns'}/resolv.conf" ) or croak "unable to write /etc/netns/$shim{'ns'}/resolv.conf";
	if ( $shim{'domainname'} ) {
		print FD qq(domain $shim{'domainname'}\n);
	} elsif ( $dhcp{'new_domain_name'} ) {
		print FD qq(domain ${dhcp{'new_domain_name'}[0]}\n);
	}
	if ( $dhcp{'new_domain_name_servers'} ) {
		foreach ( @{ $dhcp{'new_domain_name_servers'} } ) {
			print FD qq(nameserver $_\n);
		}
	}
	if ( $dhcp{'new_domain_search'} ) {
		print FD qq(search ) . join( ' ', @{ $dhcp{'new_domain_search'} } ) . qq(\n);
	}
	close(FD);
}

#
# write environment file that can be consumed by bash
#
open( FD, '>', "/tmp/env-$shim{'ns'}" ) or croak "unable to write /tmp/env-$shim{'ns'}";
foreach ( keys %shim ) {
	next unless ( $shim{$_} );
	if ( ref( $shim{$_} ) eq 'ARRAY' ) {
		print FD 'shim' . $_ . '=(' . join( ' ', @{ $shim{$_} } ) . ')' . "\n";
	} else {
		print FD 'shim' . $_ . '=' . $shim{$_} . "\n";
	}
}

foreach ( keys %router ) {
	next unless ( $router{$_} );
	if ( ref( $router{$_} ) eq 'ARRAY' ) {
		print FD 'router' . $_ . '=(' . join( ' ', @{ $router{$_} } ) . ')' . "\n";
	} else {
		print FD 'router' . $_ . '=' . $router{$_} . "\n";
	}
}

foreach ( keys %my ) {
	next unless ( $my{$_} );
	if ( ref( $my{$_} ) eq 'ARRAY' ) {
		print FD 'my' . $_ . '=(' . join( ' ', @{ $my{$_} } ) . ')' . "\n";
	} else {
		print FD 'my' . $_ . '=' . $my{$_} . "\n";
	}
}

foreach ( keys %dhcp ) {
	next unless ( $dhcp{$_} );
	if ( ref( $dhcp{$_} ) eq 'ARRAY' ) {
		print FD 'dhcp' . $_ . '=' . join( ' ', @{ $dhcp{$_} } ) . "\n";
	} else {
		print FD 'dhcp' . $_ . '=' . $dhcp{$_} . "\n";
	}
}
close(FD);

# This part takes the longest to run
# add routes for each ip in lan on routerns.  this allows inter-lan connectivity
&runcmd( 1, "ip netns exec $router{'ns'} sysctl -w net.ipv4.conf.tap1.proxy_arp=1" );
$netinfo = new Net::Netmask("$shim{'ip'}/$shim{'cidr'}");
@shimips = &getallshimips();
foreach $ip ( $netinfo->enumerate() ) {
	next if ( grep( /^$ip$/, @shimips ) );
	`ip netns exec $router{'ns'} ip route add $ip via $shim{'brip'} table $shim{'routetable'} >/dev/null 2>&1`;
}

# remove this shimip from other route tables
# we do this again in case of race condition
&removeshimroute( "$router{'ns'}", "$shim{'ip'}", "$shim{'routetable'}" );

&runcmd( 1, "ip netns exec $router{'ns'} ip route add 224.0.0.0/24 via $shim{'brip'} table $shim{'routetable'}" );

# TODO figure out multicast
# mc_forwarding

#############################################################################
# subroutines

sub runcmd() {
	my $fatality = shift;
	my $cmd      = shift;
	my @cmdout;
	my $retval;

	print qq(## $cmd\n);
	@cmdout = `$cmd`;
	$retval = $?;
	print qq(@cmdout);
	print qq(##########\n);
	if ( ( $fatality != 0 ) and ( $retval != 0 ) ) {
		croak "FATAL ERROR";
	}
	return $retval;

}

##################################################
sub printhelp() {
	print qq(
Usage: $0 --shimmac=shimmac			shimmac is required
	[--routermac=<mac>]			override routermac on inside interface (required if static lan)
	[--routerip=<ip>]			override routerip on inside interface (required if static lan)
	[--shimip=<ip>]				specify static shimip (disables dhcp)
	[--shimcidr=<cidr>]			specify shimip cidr (required if static lan)
	[--guesscidr]			    guess smallest cidr given route and shim IPs
	[--shimhostname=<hostname>]		override shimhostname
	[--vlan=<vlan id>]			specify vlan id
	[--shimdns=<dns1,dns2,dns3>]		override dns dhcpd setting
	[--shimntp=<ntp1,ntp2,ntp3>]		override ntp dhcpd setting
	[--carveports=<port,port-port>]		forward ports to shimbox, tcp and udp, from both namespaces
	[--rdrports=<origport-newport>,<..>]	redirect ports to shimbox, tcp and udp, from both namespaces and translate destination port
	[--showshims]				show shims
	[--unshim=shimnsname]				remove specific shim
	[--unshimall]				remove all shims
	[--extif]				external interface (facing router)
	[--intif]				internal interface (facing pc/lan)

NOTE: Disable NetworkManager and do not configure any interfaces.
Here is what your /etc/network/interfaces should look like if you are running Kali:
auto eth0
auto eth1
iface lo inet loopback
iface eth0 inet manual
  up ifconfig \$IFACE up
iface eth1 inet manual
  up ifconfig \$IFACE up

	);
}

##################################################
sub getnextip() {
	my @nslist;
	my $ns;
	my @ipaddrshow;
	my @iplist;
	my @usedips;
	my $netinfo;
	my $ip;
	my $enumip;

	@nslist = `ip netns list`;
	foreach $ns (@nslist) {
		chomp $ns;
		@ipaddrshow = `ip netns exec $ns ip address show tap2 2>/dev/null`;
		foreach (@ipaddrshow) {
			@iplist = split( /\s+/, $_ );
			if ( ( $iplist[1] eq "inet" ) and ( $iplist[2] =~ m/^169\.254\./ ) ) {
				$ip = $iplist[2];
				$ip =~ s/\/\d+//;
				push( @usedips, $ip );
			}
		}
	}
	@ipaddrshow = `ip address show 2>/dev/null`;
	foreach (@ipaddrshow) {
		@iplist = split( /\s+/, $_ );
		if ( ( $iplist[1] eq "inet" ) and ( $iplist[2] =~ m/^169\.254\./ ) ) {
			$ip = $iplist[2];
			$ip =~ s/\/\d+//;
			push( @usedips, $ip );
		}
	}

	$netinfo = new Net::Netmask("169.254.0.0/16");
	foreach $ip ( $netinfo->enumerate() ) {
		next if ( $ip eq '169.254.0.0' );
		next if ( grep( /^$ip$/, @usedips ) );
		$enumip = $ip;
		last;
	}
	if ( $enumip eq '169.254.255.255' ) {
		croak "out of IPs";
	} else {
		return $enumip;
	}

}

##################################################
sub getallshimips() {
	my @nslist;
	my $ns;
	my @ipaddrshow;
	my @iplist;
	my @shimips;
	my $ip;

	@nslist = `ip netns list`;
	foreach $ns (@nslist) {
		chomp $ns;
		@ipaddrshow = `ip netns exec $ns ip address show tap1 2>/dev/null`;
		foreach (@ipaddrshow) {
			@iplist = split( /\s+/, $_ );
			if ( $iplist[1] eq "inet" ) {
				$ip = $iplist[2];
				$ip =~ s/\/\d+//;
				push( @shimips, $ip );
			}
		}
	}
	return (@shimips);
}

##################################################
sub getroutetablename() {
	my $ip = shift;

	return ( unpack( "N", pack( "C4", split( /\./, $ip ) ) ) );
}

##################################################
sub removeshimroute() {
	my $namespace = shift;
	my $shimip    = shift;
	my $table     = shift;
	my @rulelist;
	my @rule;
	my @tables;

	@rulelist = `ip netns exec $namespace ip rule list`;
	foreach (@rulelist) {
		@rule = split( /\s+/, $_ );
		if ( $rule[2] =~ m/\d+\.\d+\.\d+\.\d+/ ) {
			push( @tables, $rule[4] );
		}
	}
	foreach (@tables) {
		`ip netns exec $namespace ip route del $shimip table $_ >/dev/null 2>&1`;
	}
}

##################################################
sub unshim() {
	my $shimns  = shift;
	my $envfile = "/tmp/env-${shimns}";
	my @t;
	my $routerns;
	my $routerbrip;
	my $shimip;
	my $shimroutetable;

	if ( -f "$envfile" ) {
		&runcmd( 0, "ip netns del $shimns" );
		&runcmd( 0, "brctl delif br0 br${shimns}" );
		&runcmd( 0, "ip link delete br${shimns} type veth" );
		&runcmd( 0, "brctl delif br1 ln${shimns}" );
		&runcmd( 0, "ip link delete ln${shimns} type veth" );
		open( FD, '<', "$envfile" );
		foreach (<FD>) {
			chomp;
			if ( $_ =~ /routerns=/ ) {
				@t = split( /=/, $_ );
				$routerns = $t[1];
			}
			if ( $_ =~ /routerbrip=/ ) {
				@t = split( /=/, $_ );
				$routerbrip = $t[1];
			}
			if ( $_ =~ /shimip=/ ) {
				@t = split( /=/, $_ );
				$shimip = $t[1];
			}
		}
		close(FD);
		if ( ($routerns) and ($routerbrip) ) {
			&runcmd( 0, "ip netns exec $routerns ip address del dev tap2 ${routerbrip}/16" );
		}
		if ( ($routerns) and ($shimip) ) {
			$shimroutetable = &getroutetablename("$shimip");
			&runcmd( 0, "ip netns exec $routerns ip rule del table $shimroutetable" );
		}
		unlink("envfile");

		open( FD, '+<', "/tmp/shimdhcpd-${routerns}.conf" ) or croak "unable to write /tmp/shimdhcpd-${routerns}.conf";
		flock FD, 2;
        @a = '';
		while (<FD>) {
			next if ( $_ =~ m/$shimns/ );
			push( @a, $_ );
		}
		seek FD, 0, 0;
		truncate "/tmp/shimdhcpd-${routerns}.conf", 0;
		print FD @a;
		close(FD);
		unlink("/tmp/shimdhcpd-${shimns}.conf");
	} else {
		croak "No env file for $shimns";
	}

}

##################################################
sub unshimall() {
	my @nslist;
	my @brlist;
	my @files;
	my @ipaddrshow;
	my @iplist;

	@nslist = `ip netns list`;
	foreach (@nslist) {
		chomp;
		&runcmd( 0, "ip netns del $_" );
	}

	@brlist = `brctl show`;
	foreach (@brlist) {
		chomp;
		if ( $_ =~ m|(br[SR][0-9a-f]{12})|i ) {
			&runcmd( 0, "brctl delif br0 $1" );
			&runcmd( 0, "brctl delif br1 $1" );
			&runcmd( 0, "ip link delete $1 type veth" );
		}
		if ( $_ =~ m|(ln[SR][0-9a-f]{12})|i ) {
			&runcmd( 0, "brctl delif tap0 $1" );
			&runcmd( 0, "ip link delete $1 type veth" );
		}
	}

	@files = glob("/tmp/shimdhcpd-R*.conf");
	foreach (@files) {
		unlink("$_");
	}

	@files = glob("/tmp/env-S*");
	foreach (@files) {
		unlink("$_");
	}

	@ipaddrshow = `ip address show 2>/dev/null`;
	foreach (@ipaddrshow) {
		@iplist = split( /\s+/, $_ );
		if (    ( $iplist[1] eq "inet" )
			and ( $iplist[2] =~ m/^169\.254\./ )
			and ( $iplist[2] ne '169.254.0.1/16' ) )
		{
			&runcmd( 0, "ip address del dev tap0 $iplist[2]" );
		}
	}
}

##################################################
#SHIM NAME
#OUTSIDE eth0/br0
#|	brSmac/tap1/IP
#|_	lnSmac/tap2/IP
#	|_	CORE BRIDGE tap0/IP
#		|	lnRmac/tap2/IP
#		|_	brRmac/tap1/IP
#			|_	INSIDE	eth1/br1
#

sub showshims() {
	my $env;
	my $key;
	my $val;
	my $file;
	my @envfiles = glob("/tmp/env-S*");
	my %shim;

	foreach $file (@envfiles) {
		$env = $file;
		$env =~ s|/tmp/env-||g;
		open( FD, '<', "$file" );
		while (<FD>) {
			chomp;
			next if ( $_ !~ /.+/ );
			( $key, $val ) = split( /=/, $_ );
			$shim{$env}{$key} = $val;
		}
		close(FD);
	}

	foreach $env ( keys %shim ) {
		print "SHIMNS: $env\n";
		print "ROUTERNS: $shim{$env}{'routerns'}\n";
		print "HOSTNAME: $shim{$env}{'shimhostname'}\n"      if ( $shim{$env}{'shimhostname'} );
		print "HOSTNAME: $shim{$env}{'dhcpnew_host_name'}\n" if ( $shim{$env}{'dhcpnew_host_name'} );
		print "OUTSIDE eth0/br0\n";
		print "|\t" . 'br' . $shim{$env}{'shimns'} . '/tap1/' . $shim{$env}{'shimip'} . "\n";
		print "|_\t" . 'ln' . $shim{$env}{'shimns'} . '/tap2/' . $shim{$env}{'shimbrip'} . "\n";
		print "\t|_\tCORE BRIDGE tap0/169.254.0.1\n";
		print "\t\t|\t" . 'ln' . $shim{$env}{'routerns'} . '/tap2/' . $shim{$env}{'routerbrip'} . "\n";
		print "\t\t|_\t" . 'br' . $shim{$env}{'routerns'} . '/tap1/' . $shim{$env}{'routerip'} . "\n";
		print "\t\t\t|_\tINSIDE eth1/br1\n";
		print "\n";
	}
}

##################################################
sub guesscidr() {
	my $shimip   = shift;
	my $routerip = shift;
	my $cidr     = '30';
	my $matcher;

	while ( $cidr >= 8 ) {
		$matcher = subnet_matcher "${routerip}/$cidr";
		if ( $matcher->($shimip) ) {
			return $cidr;
		}
		$cidr--;
	}

	#should never reach here
	return '24';
}
