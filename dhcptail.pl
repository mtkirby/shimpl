#!/usr/bin/perl
# 20150919 Kirby

use File::Tail;
use strict;
use Carp;

my $tsharklog = '/tmp/tshark-dhcpsniff';
my $filetail;
my $tsharkraw;
my @tshark;
my %seen;
my $hostname;
my $ip;
my $mac;
my $vlan;
my $pcap;
my @shimlog;
my $shimlog;

`which tshark >/dev/null 2>&1`;
if ( $? != 0 ) {
	croak "you need to install tshark (wireshark)";
}

`tshark -Q  -l -T fields -E separator=";" -e bootp.option.hostname -e bootp.hw.mac_addr -e bootp.ip.client -e vlan.id -n -i eth1 -Y "bootp.dhcp == 1 and udp.srcport == 68 and udp.dstport == 67" udp dst port 67 and udp src port 68 >$tsharklog 2>/dev/null &`;

my $filetail = File::Tail->new( name => "$tsharklog", maxinterval => 1, adjustafter => 2 );

while ( defined( $tsharkraw = $filetail->read ) ) {
	chomp $tsharkraw;

	# next if packet doesn't have enough data
	next if ( $tsharkraw !~ /...............+/ );
	@tshark = split( /;/, $tsharkraw );
	$hostname = $tshark[0] if ( $tshark[0] );
	$mac      = $tshark[1] if ( $tshark[1] );
	$ip       = $tshark[2] if ( $tshark[2] );
	$vlan     = $tshark[3] if ( $tshark[3] );

	$mac =~ s/,.+//g;

	print qq(RECEIVED: $hostname $mac $ip $vlan\n);

	if ( -s "$tsharklog" > 10240 ) {
		print qq(clearing log\n);
		open( FD, '>', "$tsharklog" );
		print FD '';
		close(FD);
		$pcap = glob("/tmp/wireshark_pcapng_eth1_*");
		unlink("$pcap");
	}

	next if ( $seen{$mac}++ );
	print qq(running /root/shim.pl --shimmac='$mac'\n);
	unless ( my $pid = fork ) {
#		@shimlog = `/root/shim.pl --shimmac='$mac' 2>&1`;
#		open(FD,'>',"/tmp/shimlog-$mac");
#		print FD @shimlog;
#		close(FD);
		$shimlog = '/tmp/shimlog-' . $mac;
		$shimlog =~ s/://g;
		exec("/root/shim.pl --shimmac='$mac' > $shimlog 2>&1");
		exit 0;
	}
}
