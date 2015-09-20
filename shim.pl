#!/usr/bin/perl
# 20150920 Kirby

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

my $a;
my $b;
my $carveports;
my @cmdout;
my %dhcp;
my $dhcpdpid;
my @foundrouters;
my $foundrouters;
my @foundshimips;
my $foundshimips;
my @getrouters;
my @getshimips;
my $help;
my $i;
my $ip;
my $iptcmd;
my $lockfile = '/tmp/shim.lock';
my $netinfo;
my $pid = $$;
my $rdrports;
my @rdrports;
my %rdrport;
my $routerbrip;
my $routerif = 'tap1';
my $routerip;
my $routermac;
my $routerns;
my $routernsdhcppid;
my $shimbrip;
my $shimcidr;
my @shimdns;
my $shimdns;
my $shimdomainname;
my $shimhost;
my $shimhostname;
my $shimif = 'tap1';
my $shimip;
my @shimips;
my $shimmac;
my $shimns;
my @shimntp;
my $shimntp;
my $shimroutetable;
my $shimsubnetmask;
my $showshims;
my @tshark;
my $tsharklog;
my $tsharkraw;
my $unshimall;
my $vlan;

GetOptions(
	"routermac=s"      => \$routermac,
	"routerip=s"       => \$routerip,
	"shimmac=s"        => \$shimmac,
	"shimip=s"         => \$shimip,
	"shimcidr=s"       => \$shimcidr,
	"shimhostname=s"   => \$shimhostname,
	"shimdomainname=s" => \$shimdomainname,
	"vlan=s"           => \$vlan,
	"shimdns=s"        => \$shimdns,
	"shimntp=s"        => \$shimntp,
	"carveports=s"     => \$carveports,
	"rdrports=s"       => \$rdrports,
	"showshims"        => \$showshims,
	"unshimall"        => \$unshimall,
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

`which tshark >/dev/null 2>&1`;
if ( $? != 0 ) {
	croak "you need to install tshark (wireshark)";
}

`which dhclient >/dev/null 2>&1`;
if ( $? != 0 ) {
	croak "you need to install dhclient";
}

`which dhcpd >/dev/null 2>&1`;
if ( $? != 0 ) {
	croak "you need to install dhcpd";
}

`which timeout >/dev/null 2>&1`;
if ( $? != 0 ) {
	croak "you need to install timeout";
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

if ( $shimmac !~ m/^([0-9a-f]{2}(:|$)){6}$/i ) {
	croak "bad shimmac $shimmac";
}

if ( ($shimip) and ( $shimip !~ m/\d+\.\d+\.\d+\.\d+/ ) ) {
	croak "bad shimip $shimip";
}
if ( ($routermac) and ( $routermac !~ m/^([0-9a-f]{2}(:|$)){6}$/i ) ) {
	croak "bad routermac $routermac";
}

if ( ($routerip) and ( $routerip !~ m/\d+\.\d+\.\d+\.\d+/ ) ) {
	croak "bad routerip $routerip";
}

if ( ($shimcidr) and ( $shimcidr !~ m/^\d+$/ ) ) {
	croak "bad shimcidr $shimcidr";
}
if ($shimcidr) {
	$netinfo        = new Net::Netmask("169.254.0.1/${shimcidr}");
	$shimsubnetmask = $netinfo->mask();
}

if ($shimdns) {
	@shimdns = split( /,/, $shimdns );
	foreach (@shimdns) {
		if ( $_ !~ m/^\d+\.\d+\.\d+\.\d+$/ ) {
			croak "bad shimdns $_";
		}
	}
}

if ($shimntp) {
	@shimntp = split( /,/, $shimntp );
	foreach (@shimntp) {
		if ( $_ !~ m/^\d+\.\d+\.\d+\.\d+$/ ) {
			croak "bad shimntp $_";
		}
	}
}

if ($shimip) {
	$dhcp{'dodhcp'} = 0;
	if ( !$routerip ) {
		croak "must defined routerip if shimip is specified (dhcp disabled)";
	}
	if ( !$routermac ) {
		croak "must defined routermac if shimip is specified (dhcp disabled)";
	}
	if ( !$shimcidr ) {
		croak "must defined shimcidr if shimip is specified (dhcp disabled)";
	}
} else {
	$dhcp{'dodhcp'} = 1;
}

if ( ($vlan) and ( $vlan !~ m/^\d+$/ ) ) {
	croak "bad vlan id $vlan";
}

if ($carveports) {
	$carveports =~ s/-/:/g;
	$carveports =~ s/\s+//g;
}

if ($rdrports) {
	$rdrports =~ s/\s+//g;
	@rdrports = split( /,/, $rdrports );
	foreach (@rdrports) {
		if ( $_ !~ m/\d+-\d+/ ) {
			croak "bad rdrports $rdrports";
		} else {
			( $a, $b ) = split( /-/, $_ );
			$rdrport{$a} = $b;
		}
	}
}

$shimns = 'S' . $shimmac;
$shimns =~ s/://g;
if ($routermac) {
	$routerns = 'R' . $routermac;
	$routerns =~ s/://g;
}

`ip netns exec $shimns ip link list >/dev/null 2>&1`;
if ( $? == 0 ) {
	croak "A shimns already exists for $shimmac";
}

# pre-flight check
foreach ( 'br0', 'br1' ) {
	@cmdout = `brctl show $_ 2>&1`;
	next unless ( grep( /No such device/, @cmdout ) );
	&runcmd("brctl addbr $_");
	if ( $_ eq 'br0' ) {
		&runcmd("brctl addif $_ eth0");
	} elsif ( $_ eq 'br1' ) {
		&runcmd("brctl addif $_ eth1");
	}
	&runcmd("brctl stp $_ off");
	&runcmd("ip link set dev $_ up");
}

@cmdout = `brctl show tap0 2>&1`;
if ( grep( /No such device/, @cmdout ) ) {
	&runcmd("ip link add tap0 type bridge");
	&runcmd("ip link set dev tap0 up");
	&runcmd("ip address add dev tap0 169.254.0.1/16");
}

&runcmd("sysctl -w net.ipv4.conf.all.forwarding=1");

@cmdout = `systemctl is-active NetworkManager 2>&1`;
if ( grep( /active/, @cmdout ) ) {
	&runcmd("systemctl stop NetworkManager");
}

&runcmd("modprobe br_netfilter");
&runcmd("modprobe arptable_filter");

#
# HERE IS WHERE WE START WORKING
#


# reserve brips so we can run parallel shims
while( -f "$lockfile") {
	sleep(1);
}
`touch "$lockfile"`;
$shimbrip = &getnextip();
&runcmd("ip address add dev tap0 ${shimbrip}/16");
$routerbrip = &getnextip();
&runcmd("ip address add dev tap0 ${routerbrip}/16");
unlink("$lockfile");

#fork && exit;

#
# build shim ns
#
&runcmd("ip netns add $shimns");
# use temporary tap name to avoid collisions when executing shims in parallel
# we will use the pid to make sure
&runcmd("ip link add tap1-$pid type veth peer name br${shimns}");
&runcmd("brctl addif br0 br${shimns}");
&runcmd("ip link set tap1-$pid netns $shimns");
&runcmd("ip link set dev br${shimns} up");
&runcmd("ip netns exec $shimns ip link set dev tap1-$pid name $shimif");
&runcmd("ip netns exec $shimns ip link set dev $shimif up");
&runcmd("ip netns exec $shimns ip link set dev $shimif address $shimmac");

if ($vlan) {
	&runcmd("ip link add link $shimif name $shimif type vlan id $vlan");
	$shimif .= ".$vlan";
	&runcmd("ip link set $shimif netns $shimns");
	&runcmd("ip netns exec $shimns ip link set dev $shimif address $shimmac");
}

if ( $dhcp{'dodhcp'} == 1 ) {
	open( FD, '>', "/tmp/dhclient-${shimns}.conf" );
	print FD qq(option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n);
	if ($shimhostname) {
		print FD qq(send host-name = $shimhostname;\n);
	}

	print FD
qq(request subnet-mask, broadcast-address, routers, domain-name, domain-name-servers, domain-search, host-name, netbios-name-servers, netbios-scope, netbios-dd-server, netbios-node-type, ntp-servers, bootp.option.dhcp_dns_domain_search_list_fqdn;\n);
	close(FD);

	print qq(running tshark in background\n);
	$tsharklog = "/tmp/tshark-${shimns}.out";
	unlink("$tsharklog");
	while ( !-f "$tsharklog" ) {

		# CHECK FOR BREAKAGE.  CHANGED PORTS
`timeout 5 ip netns exec $shimns tshark -l -c 1 -T fields -E separator=";" -e bootp.option.domain_name_server -e bootp.option.domain_name -e bootp.option.ntp_server -e bootp.option.subnet_mask -e bootp.option.hostname -e bootp.option.netbios_over_tcpip_dd_name_server -e bootp.option.netbios_over_tcpip_name_server -e bootp.option.netbios_over_tcpip_node_type -e bootp.option.netbios_over_tcpip_scope -n -i tap1 -Y "bootp.dhcp == 1 and udp.srcport == 67 and udp.dstport == 68"  udp src port 67 and udp dst port 68 and ether dst $shimmac >$tsharklog 2>/dev/null &`;
		sleep(2);
		&runcmd("ip netns exec $shimns dhclient -sf /root/shim-dhclient-script -cf /tmp/dhclient-${shimns}.conf $shimif");
		sleep(1);
		if ( -s "$tsharklog" < 20 ) {
			unlink("$tsharklog");
			&runcmd("pkill -f '/tmp/dhclient-${shimns}.conf'");
		}
	}
	open( FD, '<', "$tsharklog" );
	$tsharkraw = (<FD>);
	chomp $tsharkraw;
	close(FD);
	@tshark = split( /;/, $tsharkraw );
	@{ $dhcp{'dns'} } = split( /,/, $tshark[0] ) if ( $tshark[0] );
	$dhcp{'domainname'} = $tshark[1] if ( $tshark[1] );
	@{ $dhcp{'ntp'} } = split( /,/, $tshark[2] ) if ( $tshark[2] );
	$dhcp{'subnetmask'}        = $tshark[3];
	$dhcp{'hostname'}          = $tshark[4] if ( $tshark[4] );
	$dhcp{'netbios_dd_server'} = $tshark[5] if ( $tshark[5] );
	@{ $dhcp{'netbios_name_servers'} } = split( /,/, $tshark[6] ) if ( $tshark[6] );
	$dhcp{'netbios_node_type'} = $tshark[7] if ( $tshark[7] );
	$dhcp{'netbios_scope'}     = $tshark[8] if ( $tshark[8] );
	@{ $dhcp{'domain_search'} } = split( /,/, $tshark[9] ) if ( $tshark[9] );

	@getshimips = `ip netns exec $shimns ip addr show dev $shimif`;
	foreach (@getshimips) {
		chomp;
		@foundshimips = split( /\s+/, $_ );
		if ( $foundshimips[1] eq "inet" ) {
			( $shimip, $shimcidr ) = split( /\//, $foundshimips[2] );
		}
	}
} else {
	&runcmd("ip netns exec $shimns ip addr add dev $shimif $shimip/$shimcidr");
}

if ( !$routerip ) {
	&runcmd("ip netns exec $shimns ip route show");
	@getrouters = `ip netns exec $shimns ip route show`;
	foreach (@getrouters) {
		chomp;
		@foundrouters = split( /\s+/, $_ );
		if ( ( $foundrouters[0] eq "default" ) and ( $foundrouters[1] eq "via" ) ) {
			$routerip = $foundrouters[2];
		}
	}
	print qq(routerip is $routerip\n);
} else {
	&runcmd("ip netns exec $shimns ip route add default via $routerip");
}
if ( $routerip !~ m/\d+\.\d+\.\d+\.\d+/ ) {
	croak "invalid routerip $routerip";
}
if ( !$routermac ) {
	&runcmd("ip netns exec $shimns arping -r -i $shimif -C1 $routerip");
	$routermac = `ip netns exec $shimns arping -r -i $shimif -C1 $routerip`;
	chomp $routermac;
} else {
	&runcmd("ip netns exec $shimns arp -i $shimif -s $routerip $routermac");
}
if ( $routermac !~ m/^([0-9a-f]{2}(:|$)){6}$/i ) {
	print qq(BAD ROUTER MAC $routermac\n);
	print qq(BAD ROUTER IP $routerip\n);
	croak qq(Could not get mac for router);
}
$routerns = 'R' . $routermac;
$routerns =~ s/://g;

&runcmd("ip link add tap2-$pid type veth peer name ln${shimns}");
&runcmd("brctl addif tap0 ln${shimns}");
&runcmd("ip link set tap2-$pid netns $shimns");
&runcmd("ip link set dev ln${shimns} up");
&runcmd("ip netns exec $shimns ip link set dev tap2-$pid name tap2");
&runcmd("ip netns exec $shimns ip link set dev tap2 up");
&runcmd("ip address del dev tap0 ${shimbrip}/16");
&runcmd("ip netns exec $shimns ip address add dev tap2 ${shimbrip}/16");

`ip netns exec $routerns ip link list >/dev/null 2>&1`;
if ( $? != 0 ) {
	#
	# build router ns
	#
	&runcmd("ip netns add $routerns");
	&runcmd("ip link add tap1-$pid type veth peer name br${routerns}");
	&runcmd("brctl addif br1 br${routerns}");
	&runcmd("ip link set tap1-$pid netns $routerns");
	&runcmd("ip link set dev br${routerns} up");
	&runcmd("ip netns exec $routerns ip link set dev tap1-$pid name $routerif");
	&runcmd("ip netns exec $routerns ip link set dev $routerif up");
	&runcmd("ip netns exec $routerns ip link set dev $routerif address $routermac");

	if ($vlan) {
		&runcmd("ip link add link $routerif name $routerif type vlan id $vlan");
		$routerif .= ".$vlan";
		&runcmd("ip link set $routerif netns $routerns");
		&runcmd("ip netns exec $routerns ip link set dev $routerif address $routermac");
	}
	&runcmd("ip netns exec $routerns ip address add dev $routerif ${routerip}/${shimcidr}");
	&runcmd("ip link add tap2-$pid type veth peer name ln${routerns}");
	&runcmd("brctl addif tap0 ln${routerns}");
	&runcmd("ip link set dev ln${routerns} up");
	&runcmd("ip link set tap2-$pid netns $routerns");
	&runcmd("ip netns exec $routerns ip link set dev tap2-$pid name tap2");
	&runcmd("ip netns exec $routerns ip link set dev tap2 up");
}
&runcmd("ip address del dev tap0 ${routerbrip}/16");
&runcmd("ip netns exec $routerns ip address add dev tap2 ${routerbrip}/16");

$shimroutetable = &getroutetablename("$shimip");

# view routes via ip route show table <tablename>
&removeshimroute( "$routerns", "$shimip", "$shimroutetable" );
&runcmd("ip netns exec $routerns ip rule del table $shimroutetable");
&runcmd("ip netns exec $routerns ip rule add from $shimip lookup $shimroutetable");
&runcmd("ip netns exec $routerns ip route add default via $shimbrip table $shimroutetable");

if ($carveports) {
	&runcmd("ip netns exec $shimns iptables -t nat -I PREROUTING -d $shimip -p tcp -m tcp -m multiport --dports $carveports -j DNAT --to-destination 169.254.0.1");
	&runcmd("ip netns exec $shimns iptables -t nat -I PREROUTING -d $shimip -p udp -m udp -m multiport --dports $carveports -j DNAT --to-destination 169.254.0.1");
	&runcmd("ip netns exec $shimns iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p tcp -m tcp -m multiport --dports $carveports -j SNAT --to-source $shimbrip");
	&runcmd("ip netns exec $shimns iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p udp -m udp -m multiport --dports $carveports -j SNAT --to-source $shimbrip");

	&runcmd("ip netns exec $routerns iptables -t nat -I PREROUTING -s $shimip -d $routerip -p tcp -m tcp -m multiport --dports $carveports -j DNAT --to-destination 169.254.0.1");
	&runcmd("ip netns exec $routerns iptables -t nat -I PREROUTING -s $shimip -d $routerip -p udp -m udp -m multiport --dports $carveports -j DNAT --to-destination 169.254.0.1");
	&runcmd("ip netns exec $routerns iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p tcp -m tcp -m multiport --dports $carveports -j SNAT --to-source $routerbrip");
	&runcmd("ip netns exec $routerns iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p udp -m udp -m multiport --dports $carveports -j SNAT --to-source $routerbrip");
}

if (@rdrports) {
	foreach ( keys %rdrport ) {
		&runcmd("ip netns exec $shimns iptables -t nat -I PREROUTING -d $shimip -p tcp -m tcp --dport $_ -j DNAT --to-destination 169.254.0.1:$rdrport{$_}");
		&runcmd("ip netns exec $shimns iptables -t nat -I PREROUTING -d $shimip -p udp -m udp --dport $_ -j DNAT --to-destination 169.254.0.1:$rdrport{$_}");
		&runcmd("ip netns exec $shimns iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p tcp -m tcp --dport $rdrport{$_} -j SNAT --to-source $shimbrip");
		&runcmd("ip netns exec $shimns iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p udp -m udp --dport $rdrport{$_} -j SNAT --to-source $shimbrip");

		&runcmd("ip netns exec $routerns iptables -t nat -I PREROUTING -s $shimip -p tcp -m tcp --dport $_ -j DNAT --to-destination 169.254.0.1:$rdrport{$_}");
		&runcmd("ip netns exec $routerns iptables -t nat -I PREROUTING -s $shimip -p udp -m udp --dport $_ -j DNAT --to-destination 169.254.0.1:$rdrport{$_}");
		&runcmd("ip netns exec $routerns iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p tcp -m tcp --dport $rdrport{$_} -j SNAT --to-source $routerbrip");
		&runcmd("ip netns exec $routerns iptables -t nat -I POSTROUTING -d 169.254.0.1 -o tap2 -p udp -m udp --dport $rdrport{$_} -j SNAT --to-source $routerbrip");
	}
}

&runcmd("ip netns exec $shimns iptables -t nat -A PREROUTING -d $shimip ! -p icmp -j DNAT --to-destination $routerbrip");
&runcmd("ip netns exec $shimns iptables -t nat -A PREROUTING -d $shimbrip ! -p icmp -j DNAT --to-destination $routerip");
&runcmd("ip netns exec $shimns iptables -t nat -A POSTROUTING -o $shimif ! -d 169.254.0.0/16 -j SNAT --to $shimip");

&runcmd("ip netns exec $routerns iptables -t nat -A PREROUTING -d $routerip ! -p icmp -j DNAT --to-destination $shimbrip");
&runcmd("ip netns exec $routerns iptables -t nat -A PREROUTING -d $routerbrip ! -p icmp -j DNAT --to-destination $shimip");
&runcmd("ip netns exec $routerns iptables -t nat -A POSTROUTING -s $shimip -j SNAT --to $routerbrip");

# hide from traceroutes
&runcmd("ip netns exec $routerns iptables -t mangle -D PREROUTING -m ttl --ttl-gt 1  -j TTL --ttl-inc 2");
&runcmd("ip netns exec $routerns iptables -t mangle -A PREROUTING -m ttl --ttl-gt 1  -j TTL --ttl-inc 2");

# prevent dhcp clients from detecting a duplicate ip
&runcmd("ip netns exec $routerns arptables -I INPUT -s $shimip -d $shimip -j DROP");

# safeguard
# In the case that someone reverses the cables.
# We don't want the shimbox to answer as the router on the outside interface.
&runcmd("ip netns exec $routerns arptables -D INPUT -i $routerif -j DROP");
&runcmd("ip netns exec $routerns arptables -A INPUT -i $routerif -s $shimip -j ACCEPT");
&runcmd("ip netns exec $routerns arptables -A INPUT -i $routerif --source-mac $shimmac -j ACCEPT");
&runcmd("ip netns exec $routerns arptables -A INPUT -i $routerif -j DROP");

&runcmd("ip netns exec $shimns arptables -D INPUT -i $shimif -j DROP");
&runcmd("ip netns exec $shimns arptables -A INPUT -i $shimif -d $shimip -j ACCEPT");
&runcmd("ip netns exec $shimns arptables -A INPUT -i $shimif --destination-mac $shimmac -j ACCEPT");
&runcmd("ip netns exec $shimns arptables -A INPUT -i $shimif -j DROP");

&runcmd("ip netns exec $routerns arp -s $shimip $shimmac");

if ( $dhcp{'dodhcp'} == 1 ) {
	if ( -f "/etc/netns/$shimns/resolv.conf" ) {
		unlink("/etc/netns/$shimns/resolv.conf");
	}

	unless ( -f "/tmp/shimdhcpd-${routerns}.conf" ) {
		open( FD, '>', "/tmp/shimdhcpd-${routerns}.conf" );
		print FD qq(ddns-update-style none;\n);
		print FD qq(default-lease-time 36000;\n);
		print FD qq(max-lease-time 72000;\n);
		print FD qq(log-facility local7;\n);
		print FD qq(subnet 0.0.0.0 netmask 0.0.0.0 {\n);
		print FD qq(}\n);
		close(FD);
	}
	open( FD, '<', "/tmp/shimdhcpd-${routerns}.conf" );
	$dhcp{'addhost'} = 1;
	while (<FD>) {
		if ( $_ =~ m/fixed-address ${shimip}; / ) {
			$dhcp{'addhost'} = 0;
		}
	}
	close(FD);
	if ( $dhcp{'addhost'} == 1 ) {
		open( FD, '>>', "/tmp/shimdhcpd-${routerns}.conf" );
		print FD qq(host $shimns {\n);
		print FD qq(	hardware ethernet $shimmac;\n);
		print FD qq(	fixed-address $shimip;\n);
		print FD qq(	option routers $routerip;\n);
		if ($shimhostname) {
			print FD qq(	option host-name "$shimhostname";\n);
		} elsif ( $dhcp{'hostname'} ) {
			print FD qq(	option host-name "$dhcp{'hostname'}";\n);
		}
		if ($shimdomainname) {
			print FD qq(	option domain-name "$shimdomainname";\n);
		} elsif ( $dhcp{'domainname'} ) {
			print FD qq(	option domain-name "$dhcp{'domainname'}";\n);
		}
		if ( $dhcp{'subnetmask'} ) {
			print FD qq(	option subnet-mask $dhcp{'subnetmask'};\n);
		}
		if ( $dhcp{'dns'} ) {
			print FD qq(	option domain-name-servers ) . join( ', ', @{ $dhcp{'dns'} } ) . qq(;\n);
		}
		if ( $dhcp{'ntp'} ) {
			print FD qq(	option ntp-servers ) . join( ', ', @{ $dhcp{'ntp'} } ) . qq(;\n);
		}
		if ( $dhcp{'netetbios_dd_server'} ) {
			print FD qq(	option netbios-dd-server $dhcp{'netbios_dd_server'};\n);
		}
		if ( $dhcp{'netbios_name_servers'} ) {
			print FD qq(	option netbios-name-servers ) . join( ', ', @{ $dhcp{'netbios_name_servers'} } ) . qq(;\n);
		}
		if ( $dhcp{'netbios_node_type'} ) {
			print FD qq(	option netbios-node-type $dhcp{'netbios_node_type'};\n);
		}
		if ( $dhcp{'netbios_scope'} ) {
			print FD qq(	option netbios-scope $dhcp{'netbios_scope'};\n);
		}
		if ( $dhcp{'domain_search'} ) {
			print FD qq(	option domain-search ) . join( ', ', @{ $dhcp{'domain_search'} } ) . qq(;\n);
		}
		print FD qq(}\n);
		close(FD);

		$routernsdhcppid = "/var/run/dhcpd-${routerns}.pid";
		if ( -f "$routernsdhcppid" ) {
			open( FD, '<', "$routernsdhcppid" );
			$dhcpdpid = (<FD>);
			chomp $dhcpdpid;
			`kill $dhcpdpid`;
			close(FD);
			unlink "$routernsdhcppid";
		}
		`touch /var/lib/dhcp/dhcpd-${routerns}.leases`;
		&runcmd("ip netns exec $routerns /usr/sbin/dhcpd -q -lf /var/lib/dhcp/dhcpd-${routerns}.leases -cf /tmp/shimdhcpd-${routerns}.conf -pf /var/run/dhcpd-${routerns}.pid $routerif");
	}

	mkdir( "/etc/netns",         0755 );
	mkdir( "/etc/netns/$shimns", 0755 );
	open( FD, '>', "/etc/netns/$shimns/resolv.conf" );
	if ($shimdomainname) {
		print FD qq(domain $shimdomainname\n);
	} elsif ( $dhcp{'domainname'} ) {
		print FD qq(domain $dhcp{'domainname'}\n);
	}
	if ( $dhcp{'dns'} ) {
		foreach ( @{ $dhcp{'dns'} } ) {
			print FD qq(nameserver $_\n);
		}
	}
	if ( $dhcp{'domain_search'} ) {
		foreach ( @{ $dhcp{'domain_search'} } ) {
			print FD qq(nameserver $_\n);
		}
	}
	close(FD);
}

#
# write environment file that can be consumed by bash
#
open( FD, '>', "/tmp/env-$shimns" );
print FD qq(
routerbrip=$routerbrip
routerip=$routerip
routermac=$routermac
routerns=$routerns
shimbrip=$shimbrip
shimip=$shimip
shimmac=$shimmac
shimns=$shimns
);
print FD qq(shimhostname=$shimhostname\n)     if ($shimhostname);
print FD qq(shimdomainname=$shimdomainname\n) if ($shimdomainname);
print FD 'shimdns=(' . join( ' ', @shimdns ) . ')' . qq("\n) if (@shimdns);
print FD 'shimntp=(' . join( ' ', @shimntp ) . ')' . qq("\n) if (@shimntp);
foreach ( keys %dhcp ) {

	if ( ref( $dhcp{$_} ) eq 'ARRAY' ) {
		print FD 'dhcp' . $_ . '=(' . join( ' ', @{ $dhcp{$_} } ) . ')' . "\n";
	} else {
		print FD 'dhcp' . $_ . '=' . $dhcp{$_} . "\n";
	}
}
close(FD);


# This part takes the longest to run
# add routes for each ip in lan on routerns.  this allows inter-lan connectivity
&runcmd("ip netns exec $routerns sysctl -w net.ipv4.conf.tap1.proxy_arp=1");
$netinfo = new Net::Netmask("${shimip}/${shimcidr}");
@shimips = &getallshimips();
for $ip ( $netinfo->enumerate() ) {
	next if ( grep( /^$ip$/, @shimips ) );
	`ip netns exec $routerns ip route add $ip via $shimbrip table $shimroutetable >/dev/null 2>&1`;
}

# remove this shimip from other route tables
# we do this again in case of race condition
&removeshimroute( "$routerns", "$shimip", "$shimroutetable" );

#`ip netns exec $routerns ip route add 224.0.0.0/24 via $shimbrip >/dev/null 2>&1`;
# TODO figure out multicast
# mc_forwarding

#############################################################################
# subroutines

sub runcmd() {
	my $cmd = shift;
	my @cmdout;
	my $retval;

	print qq(##########\n);
	print qq(running $cmd\n);
	@cmdout = `$cmd`;
	$retval = $?;
	print qq(@cmdout);
	print qq(##########\n);
	return $retval;
}

sub printhelp() {
	print qq(
Usage: $0 --shimmac=shimmac			shimmac is required
	[--routermac=<mac>]			override routermac on inside interface (required if static lan)
	[--routerip=<ip>]			override routerip on inside interface (required if static lan)
	[--shimip=<ip>]				specify static shimip (disables dhcp)
	[--shimcidr=<cidr>]			specify shimip cidr (required if static lan)
	[--shimhostname=<hostname>]		override shimhostname
	[--vlan=<vlan id>]			specify vlan id
	[--shimdns=<dns1,dns2,dns3>]		override dns dhcpd setting
	[--shimntp=<ntp1,ntp2,ntp3>]		override ntp dhcpd setting
	[--carveports=<port,port-port>]		forward ports to shimbox, tcp and udp, from both namespaces
	[--rdrports=<origport-newport>,<..>]	redirect ports to shimbox, tcp and udp, from both namespaces and translate destination port
	[--showshims]				show shims
	[--unshimall]				remove all shims

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

sub getroutetablename() {
	my $ip = shift;
	my @sip = split( /\./, $ip );
	my $tablename;
	$tablename = sprintf "%03d", "$sip[0]";
	$tablename .= sprintf "%03d", "$sip[1]";
	$tablename .= sprintf "%03d", "$sip[2]";
	$tablename .= sprintf "%03d", "$sip[3]";
	return ($tablename);
}

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

sub unshimall() {
	my @nslist;
	my @brlist;
	my @files;
	my @ipaddrshow;
	my @iplist;

	@nslist = `ip netns list`;
	foreach (@nslist) {
		chomp;
		&runcmd("ip netns del $_");
	}

	@brlist = `brctl show`;
	foreach (@brlist) {
		chomp;
		if ( $_ =~ m|(br[SR][0-9a-f]{12})|i ) {
			&runcmd("brctl delif br0 $1");
			&runcmd("brctl delif br1 $1");
			&runcmd("ip link delete $1 type veth");
		}
		if ( $_ =~ m|(ln[SR][0-9a-f]{12})|i ) {
			&runcmd("brctl delif tap0 $1");
			&runcmd("ip link delete $1 type veth");
		}
	}

	@files = glob("/tmp/shimdhcpd-R*.conf");
	foreach (@files) {
		unlink("$_");
	}

	@ipaddrshow = `ip address show 2>/dev/null`;
	foreach (@ipaddrshow) {
		@iplist = split( /\s+/, $_ );
		if ( ( $iplist[1] eq "inet" ) and ( $iplist[2] =~ m/^169\.254\./ ) and ( $iplist[2] ne '169.254.0.1/16' ) ) {
			&runcmd("ip address del dev tap0 $iplist[2]");
		}
	}
}

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
		print "HOSTNAME: $shim{$env}{'shimhostname'}\n" if ( $shim{$env}{'shimhostname'} );
		print "HOSTNAME: $shim{$env}{'dhcphostname'}\n" if ( $shim{$env}{'dhcphostname'} );
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
