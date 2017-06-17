#!/usr/bin/perl

# IKEProbe 1.12
# By Anton T. Rager - arager@avaya.com
# 
# 2/14/2002 - V.01 Initial script for basic IKE testing completed
# 3/29/2002 - V1.01 Commandline option processing - options were hardcoded before
# 4/3/2002 - V1.02 Added more options: eac, main, sa_tests
# 4/4/2002 - V1.10 Rewrote transform section for multiple transforms
# 5/19/2002 - V1.11 Added option for IP_V4 ID, cookie randomizer for init/resp
# 8/14/2002 - V1.12 Fixed IP_V4 stuff for RAW Hex ID - still having probs with Ascii IP
# 9/25/2000 - V1.13 Code cleanup and renamed to IKEProber
#
# This tool crafts IKE initiator packets and allows many options to be
# manually set.  It's useful for finding overflows, error conditions,
# and identifying vendors
#


use IPC::Open2;

	$responder=1;
	$ex_type="04"; # Aggressive
	$spiopt="00";
	$sa_test=0;
print("ikeprober.pl V1.13 -- 02/14/2002, updated 9/25/2002\n\tBy: Anton T. Rager - arager@avaya.com\n\n");

if (substr(@ARGV[0],0,1) eq "-") {
	$argflag = 1;
} else {
	print("Error: Must supply options\n");
	&usage;
}
while ($argflag eq 1) {

	if (@ARGV[0] eq "-s") { # specifiy SA proposal
		@sa_prop = split(":",@ARGV[1]);
		$ike_encr = $sa_prop[0];
		$ike_hash = $sa_prop[1];
		$ike_auth = $sa_prop[2];
		$ike_group = $sa_prop[3];
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove SA info
		push(@ike_order, "01");
	} elsif (@ARGV[0] eq "-d") { # initiator packet to specified host
		$remote_host=@ARGV[1];
		$responder=0;
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove host info
	} elsif (@ARGV[0] eq "-v") { # Vendor ID option
		$vend_txt="";
		$vendopt=@ARGV[1];
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove vendorID info
		push(@ike_order, "0d");
		if ($vendopt eq "auser" || $vendopt eq "user") {
			$vend_txt=@ARGV[0];
			shift(@ARGV); # Remove text info
		}
	} elsif (@ARGV[0] eq "-n") { # Nonce option
		$nonce_txt="";
		$nonceopt=@ARGV[1];
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove Nonce info
		push(@ike_order, "0a");
		if ($nonceopt eq "auser" || $nonceopt eq "user") {
			$nonce_txt=@ARGV[0];
			shift(@ARGV); # Remove text info
		}
	} elsif (@ARGV[0] eq "-k") { # KE option
		$ke_txt="";
		$keopt=@ARGV[1];
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove KE info
		push(@ike_order, "04");
		if ($keopt eq "auser" || $keopt eq "user") {
			$ke_txt=@ARGV[0];
			shift(@ARGV); # Remove text info
		}
	} elsif (@ARGV[0] eq "-h") { # Hash option
		$hash_txt="";
		$hashopt=@ARGV[1];
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove Hash info
		push(@ike_order, "08");
		if ($hashopt eq "auser" || $hashopt eq "user") {
			$hash_txt=@ARGV[0];
			shift(@ARGV); # Remove text info
		}
	} elsif (@ARGV[0] eq "-i") { # IKE ID option
		$id_txt="";
		$idopt=@ARGV[1];
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove ID info
		push(@ike_order, "05");
		if ($idopt eq "auser" || $idopt eq "user" || $idopt eq "ip" || $idopt eq "ipraw") {
			$id_txt=@ARGV[0];
			shift(@ARGV); # Remove text info
		}
	} elsif (@ARGV[0] eq "-r") { # Repeat last option X times
		$repeatopt=@ARGV[1];
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove vendorID info
		$repeater = $ike_order[scalar(@ike_order)-1];
		for ($x = 0; $x < $repeatopt; $x++) {
		push(@ike_order, $repeater); # repeat last value in @ike_order
		}
	} elsif (@ARGV[0] eq "-spi") { # Repeat last option X times
		$spiopt=@ARGV[1];
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove SPI info
	} elsif (@ARGV[0] eq "-main") { # Repeat last option X times
		$ex_type="02";
		shift(@ARGV); # Remove option


	} elsif (@ARGV[0] eq "-rand") { # Randomize cookie
		$rnd_cookie=1;
		shift(@ARGV); # Remove option

	} elsif (@ARGV[0] eq "-eac") { # Nortel EAC
		$eac=1;
		shift(@ARGV); # Remove option

	} elsif (@ARGV[0] eq "-sa_test") {
	# Special SA tests:
	#1=86400 lifetime, 2=ff:ff:ff:ff duration, 3=86400 duration repeated X times, 4=TLV with value of X
		$sa_test=@ARGV[1];
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove test_num info

	} elsif (@ARGV[0] eq "-transforms") {
	# Specify number of times to repeat transform:

		$transforms=@ARGV[1];
		shift(@ARGV); # Remove option
		shift(@ARGV); # Remove test_num info			
	
	} else {
		print("Error: Invalid Options\n");
		&usage;
	}
	$argflag=0;
	if (substr(@ARGV[0],0,1) eq "\-") {
		$argflag = 1;
	}
}

push(@ike_order, "00"); # Add "None" Payload in @ike_order for end of array

print("Option order: @ike_order\n");


if ($responder) {
	print("Responder Mode: waiting for IKE packet\n");
	open2 (*README, *WRITEME, "nc -u -l -p 500");
	$in_packet = <README>;
	$hex_in_packet=unpack("H*", pack("A*", $in_packet));
	$init_cookie=substr($hex_in_packet, 0, 16);
#	print("RXed Init\n Sleeping 4sec\n");
#	sleep 4;
} else {
	print("Initiator Mode: Sending IKE packet to $remote_host\n");
	open2 (*README, *WRITEME, "nc -u -p 500 $remote_host 500");
	if ($rnd_cookie) {
		for ($x=0; $x<8; $x++) {
			$init_cookie = $init_cookie . unpack("H*", pack("c", rand(255)));
		}
	} else {
		$init_cookie="0000000000000000";
	}
}

if ($rnd_cookie && $responder) {
	for ($x=0; $x<8; $x++) {
		$resp_cookie = $resp_cookie . unpack("H*", pack("c", rand(255)));
	}
} else {
	$resp_cookie="0000000000000000";
}


#Default aggr header

print("Cookies: $init_cookie:$resp_cookie\n");

#$nxt_payload="01";
$version="10";
#$version="10";

# Exchange 04=aggr, 02=main
#$ex_type="04";

# Flags xxxxxxxx
#            ace
# a=04, c=02, e=01
$flags="00";


$msg_id="00000000";
# 4bytes - calculate after filling frame
#$ike_len="00000000";

# end header


# Next Frame Codes
# 01 - SA
# 04 - KE
# 0a - nonce
# 05 - ID
# 0d - Vendor
# 08 - hash


for ($looper=0; $looper < scalar(@ike_order)-1; $looper++) {

	if ($ike_order[$looper] eq "01") { # SA
	  $buildframe = $buildframe . make_sa($ike_order[$looper+1], $ike_encr, $ike_hash, $ike_auth, $ike_group);
	} elsif ($ike_order[$looper] eq "04") { # ke
	  $buildframe = $buildframe . make_generic($ike_order[$looper+1], $keopt, $ke_txt); #number/user
	} elsif ($ike_order[$looper] eq "0a") { # nonce
	  $buildframe = $buildframe . make_generic($ike_order[$looper+1], $nonceopt, $nonce_txt); #number/user
	} elsif ($ike_order[$looper] eq "05") { # ID
	  $buildframe = $buildframe . make_id($ike_order[$looper+1], $idopt, $id_txt); #number/user/auser
	} elsif ($ike_order[$looper] eq "0d") {
	  $buildframe = $buildframe . make_generic($ike_order[$looper+1], $vendopt, $vend_txt); #number/user/auser
	} elsif ($ike_order[$looper] eq "08") { # hash
	  $buildframe = $buildframe . make_generic($ike_order[$looper+1], $hashopt, $hash_txt); #number/user/auser
	}

}

$nxt_payload = $ike_order[0];

$outframe = $init_cookie . $resp_cookie;
$outframe = $outframe . $nxt_payload;
$outframe = $outframe . $version;
$outframe = $outframe . $ex_type;
$outframe = $outframe . $flags;
$outframe = $outframe . $msg_id;

# Calculate IKE length field. Field can be manually set via options

#$ike_len="ffffffff";
#$ike_len="00000000";

if (!$ike_len) {

	$ike_len = (length($buildframe)+length($outframe) + 8)/2;
	# /
	if ($ike_len + 42 > 1510) {
		print("Alert: packet ($ike_len bytes) will create fragment with IP header\n");
	}
	#convert decimal length to 4byte hex string
	$ike_hex_len = unpack("H*", pack("N", $ike_len));
}

$outframe = $outframe . $ike_hex_len;
$outframe = $outframe . $buildframe;

$char_outframe=unpack("A*", pack("H*", $outframe));
print(WRITEME $char_outframe);
close (WRITEME);
close (README);


sub make_sa {
	local ($nxt, $encr, $hash, $auth, $group, $special) = @_;
	my $sa;

# SA header
# nxt_payload
$sa_head1=$nxt;
# resv 00
$sa_head1=$sa_head1 . "00";
# len - calc [xx:xx]
# DOI = 00:00:00:01
$sa_head2="00000001";
# situation IDENTITY = 00:00:00:01
$sa_head2=$sa_head2 . "00000001";
# Proposal header
# nxt_payload none = 00
$sa_prop1="00";
# resv 00
$sa_prop1=$sa_prop1 . "00";
# len - calc [xx:xx]
# proposal #1 : 01
$sa_prop2="01";
# protoID ISAKMP : 01
$sa_prop2 = $sa_prop2 . "01";
# SPI size 0 :  00
$spi=$spiopt;
$sa_prop2 = $sa_prop2 . $spi;

# number transforms 1 : 01

if (!$transforms) {
	$transforms = 1;
}

$sa_prop2 = $sa_prop2 . unpack("H*", pack("c", $transforms));

# create SPI if SPI size is non-zero
for ($z=0; $z<hex($spi); $z++) {
	$sa_prop2 = $sa_prop2 . "ee";
}

# Transform header
# nxt_payload none = 00


for ($transloop=0; $transloop < $transforms; $transloop++) {

	# - nxt payload is "03" unless last transform
	if ($transloop eq $transforms-1) {
		$sa_trans1 = "00"; # Nxt payload is none
	} else {
		$sa_trans1 = "03"; # Nxt payload is transform
	}	
	# resv 00
	$sa_trans1 = $sa_trans1 . "00";

	# len - calc [xx:xx]
	# transform number 1 : 01
	$sa_trans2=unpack("H*", pack("c", $transloop+1));
	#$sa_trans2="01";

	# transformID KEY_IKE : 01
	$sa_trans2=$sa_trans2 . "01";
	# resv 00:00
	$sa_trans2=$sa_trans2 . "0000";
	# -- ENCR 80:01:00:01 [des]
	# -- hash 80:02:00:01 [md5]
	# -- auth 80:03:00:01 [psk]
	# -- group 80:04:00:01 [1]
	# -- lifetype sec 80:0b:00:01
	# -- lifeduration 80:0c:70:80 [28800]

	# trans number, transform
	if ($encr eq "des") {
		$sa_trans2=$sa_trans2 . "80010001";
	} elsif ($encr eq "3des") {
		$sa_trans2=$sa_trans2 . "80010005";
	} else {
		$sa_trans2=$sa_trans2 . "800100";
		$sa_trans2=$sa_trans2 . $encr;
	}



	if ($hash eq "md5") {
		$sa_trans2=$sa_trans2 . "80020001";
	} elsif ($hash eq "sha1") {
		$sa_trans2=$sa_trans2 . "80020002";
	} else {
		$sa_trans2=$sa_trans2 . "800200";
		$sa_trans2=$sa_trans2 . $hash;
	}

	if ($auth eq "psk") {
		$sa_trans2=$sa_trans2 . "80030001";
	} else {
		$sa_trans2=$sa_trans2 . "800300";
		$sa_trans2=$sa_trans2 . $auth;
	}

	if ($group eq "1") {
		$sa_trans2=$sa_trans2 . "80040001";
	} elsif ($group eq "2") {
		$sa_trans2=$sa_trans2 . "80040002";
	} else {
		$sa_trans2=$sa_trans2 . "800400";
		$sa_trans2=$sa_trans2 . $group;
	}


	if ($sa_test eq 1) {
		#Life Type in Seconds
		$sa_trans2=$sa_trans2 . "800b0001";
		$sa_trans2=$sa_trans2 . "000c000400015180"; #86400
	} elsif ($sa_test eq 2) {
		#Life Type in Seconds
		$sa_trans2=$sa_trans2 . "800b0001";
		$sa_trans2=$sa_trans2 . "000c0004ffffffff"; #FFFFFFFF
	} elsif ($sa_test eq 3) {
		# Large number of attributes
		$sa_trans2=$sa_trans2 . "800b0001";
		$sa_trans2=$sa_trans2 . "000c000400015180"; #86400
		for ($z=0; $z<192; $z++) {
			$sa_trans2=$sa_trans2 . "80040002";
					#TLV, ID=0c, len=04, val=00-01-51-80
		}
	} elsif ($sa_test eq 4) {
		# attributes with large payloads
		# 2byte attribute ID
		# 2 types of attribute fields: T/L/V or Tyupe with 2byte len
		# AF|ID|2byte:len/val|
		# example: duration with unreasonable value of 256 x FF
		$sa_trans2=$sa_trans2 . "800b0001";
		$sa_trans2=$sa_trans2 . "000c000400015180"; #86400
		$tlv_len=1200;
		$sa_trans2=$sa_trans2 . "0004";  # TLV datatype
		$tlv_hex_len = unpack("H*", pack("n", $tlv_len)); # TLV len as 2byte hex
		$sa_trans2=$sa_trans2 . $tlv_hex_len;

		for ($z=0; $z < $tlv_len; $z++) {  # pad TLV data with correct length
			$sa_trans2=$sa_trans2 . "ff";
		}
	} elsif ($sa_test eq 5) {
		#Life Type in Seconds
		$sa_trans2=$sa_trans2 . "800b0001";
		$sa_trans2=$sa_trans2 . "000c0004000d2f00"; #864000
	}

	if ($eac) {
		$sa_trans2=$sa_trans2 . "ffff0006" # Nortel EAC Transform ID
	}

	# sa_trans1 +4 + sa_trans2 => sa_trans_len
	$sa_trans_len = (length($sa_trans1)+length($sa_trans2)+4)/2;
	# /
	#convert decimal length to 2byte hex string
	$sa_trans_hex_len = unpack("H*", pack("n", $sa_trans_len));
	$sa_trans = $sa_trans . $sa_trans1;
	$sa_trans = $sa_trans . $sa_trans_hex_len;
	$sa_trans = $sa_trans . $sa_trans2;
	$sa_alltrans_len=$sa_alltrans_len + $sa_trans_len;

}


# sa_prop1 +4 + sa_prop2 + sa_trans_len = > sa_prop_len
$sa_prop_len = (length($sa_prop1)+length($sa_prop2)+($sa_alltrans_len*2)+4)/2;
# /
#convert decimal length to 2byte hex string
$sa_prop_hex_len = unpack("H*", pack("n", $sa_prop_len));
$sa_prop = $sa_prop1 . $sa_prop_hex_len;
$sa_prop = $sa_prop . $sa_prop2;
$sa_prop = $sa_prop . $sa_trans;

# sa_head1 + 4 + sa_head2 + sa_prop_len => sa_head_len
$sa_head_len = (length($sa_head1)+length($sa_head2)+($sa_prop_len*2)+4)/2;
# /
#convert decimal length to 2byte hex string
$sa_head_hex_len = unpack("H*", pack("n", $sa_head_len));
$sa_head = $sa_head1 . $sa_head_hex_len;
$sa_head = $sa_head . $sa_head2;
$sa_head = $sa_head . $sa_prop;


#$sa_head=$sa . $sa_trans2;

return $sa_head;
}


sub make_id {
	local ($nxt, $option, $uid) = @_;
	my $id, $tempid, $id_len, $id_hex_len;

# Per RFC2407
#
# RESERVED                            0
# ID_IPV4_ADDR                        1
# ID_FQDN                             2
# ID_USER_FQDN                        3
# ID_IPV4_ADDR_SUBNET                 4
# ID_IPV6_ADDR                        5
# ID_IPV6_ADDR_SUBNET                 6
# ID_IPV4_ADDR_RANGE                  7
# ID_IPV6_ADDR_RANGE                  8
# ID_DER_ASN1_DN                      9
# ID_DER_ASN1_GN                      10
# ID_KEY_ID                           11


$id=$nxt;
$id=$id . "00"; # resv

if ($option eq "ip" || $option eq "ipraw") {
	$id_type="01"; #IPV4_ADDR
} else {
	$id_type= "03"; #USER_FQDN
}

$tempid=$id_type ; # ID Type
$tempid=$tempid . "00"; # unused proto ID
$tempid=$tempid . "0000"; #unused port number


if ($option eq "user") {
	$tempid=$tempid . $uid;
} elsif ($option eq "auser") {
	$uid_hex = unpack("H*", pack("A*", $uid));
	$tempid=$tempid . $uid_hex;
} elsif ($option eq "ip") {
	@ip_addr=split(".", $uid);
        print("IP = $uid : Array = @ip_addr");
	$uid_hex = unpack("H*", pack("C*", @ip_addr));
	$tempid=$tempid . $uid_hex;
        print(": HEX_IP = $uid_hex\n");
} elsif ($option eq "ipraw") {
	$tempid=$tempid . $uid;
} else {
	for ($x=0; $x<$option-8; $x++) {
		$tempid=$tempid . "ff";
	}
}

$id_len = (length($tempid)+length($id)+4)/2;
# /
#convert decimal length to 2byte hex string
$id_hex_len = unpack("H*", pack("n", $id_len));

$id=$id . $id_hex_len;
$id=$id . $tempid;
return $id;
}

sub make_generic {
	local ($nxt, $option, $value) = @_;
	my $payload, $temppayload, $payload_len, $payload_hex_len;

$payload=$nxt;
$payload=$payload . "00"; # resv
$temppayload="";

if ($option eq "user") {
	$temppayload=$temppayload . $value;
} elsif ($option eq "auser") {
	$payload_hex = unpack("H*", pack("A*", $value));
	$temppayload=$temppayload . $payload_hex;
} else {
	for ($x=0; $x<$option-4; $x++) {
		$temppayload=$temppayload . "ff";
	}
}

$payload_len = (length($temppayload)+length($payload)+4)/2;
# /
#convert decimal length to 2byte hex string
$payload_hex_len = unpack("H*", pack("n", $payload_len));

$payload=$payload . $payload_hex_len;
$payload=$payload . $temppayload;
return $payload;
}

sub usage {

die("Usage:
\t-s SA [encr:hash:auth:group]
\t-k x|auser value|user value [KE repeatedX times|ascii_supplied|hex_supplied]
\t-n x|auser value|user value [Nonce repeatedX times|ascii_supplied|hex_supplied]
\t-v x|auser value|user value [VendorID repeatedX|ascii_supplied|hex_supplied]
\t-i x|auser value|user|rawip value [ID repeatedX|ascii_supplied|hex_supplied|Hex_IPV4]
\t-h x|auser value|user value [Hash repeatedX|ascii_supplied|hex_supplied]
\t-spi xx [SPI in 1byte hex]
\t-r x [repeat previous payload x times]
\t-d ip_address [Create Init packet to dest host]
\t-eac [Nortel EAC transform - responder only]
\t-main [main mode packet instead of aggressive mode - logic will be added later for correct init/respond]
\t-sa_test 1|2|3|4 [1=86400sec life, 2=0xffffffff life, 3=192 group attribs, 4=128 byte TLV attrib]
\t-rand randomize cookie
\t-transforms x [repeat SA transform x times]
");

}
