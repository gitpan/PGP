#!/usr/local/bin/perl
# Make sure you use perl 5.000 or higher!  This program won't even
# compile with a lower one.

# PGPACKET
# PGP Packet analyzer, by Mark E. Shoulson (shoulson@cs.columbia.edu)

# (c) Mark E. Shoulson 1995
# Version 1.0, 31 May 1995

# Permission is granted to distribute this program freely and make 
# modifications or improvements.  Please keep the name of the author on
# modified versions, AND note modifications as the products of those
# who made them.

# Please let me know if you like this program.

# This program takes any PGP output (*non-armored*) and prints out a
# report of each packet it comes across (what type, what's in it, etc).
# It's not going to crack anything or do any real work (like uncompressing
# or decrypting); it just analyzes the structure of the file.

# If all you have is an ascii-armored file, try using stuff with 
# pgp +keepbinary -d and all to de-armor it and leave the rest to poke with.
# Ditto signed, compressed but unencrypted files, etc.

# Actual data is generally not printed, except for N and E of public keys
# and user-ID information.  Other information may be parsed out and displayed,
# but I don't see much reason to print out the encrypted D or encrypted data.
# I read all the stuff in anyway, often wasting variables and space on it,
# in case you actually want to do anything with it.

# Some symbolic names for CTB's...
# Manifest constants would be better, but who cares?
# CTB types:

$CTB_PKE=01;			# Public-Key Encrypted
$CTB_SKE=02;			# Secret-Key Encypted (signature)
$CTB_SEC=05;			# Secret Key Certificate
$CTB_PUB=06;			# Public Key Certificate
$CTB_COMP=010;			# Compressed Data
$CTB_CKE=011;			# Conventional-Key Encrypted
$CTB_RAW=013;			# Raw literal data, filename and mode
$CTB_TRUST=014;			# Keyring Trust Packet
$CTB_UID=015;			# User ID Packet
$CTB_CMT=016;			# Comment Packet

sub ctb {
    # Stolen from Adam Back's extract-pub, slightly modified for my 
    # own stylistic preferences.

    my ($c,$d,$ct,$lf,$n,$len);
    # This is the only EOF check in the program, aside from packets
    # which read the rest of the file.  So it won't be terribly 
    # clean with files that end in the wrong places.  Cope.
    return () if eof(PGP);
    $d = getc(PGP);
    $c=unpack('C',$d);
    $ct=$c&074;
    $ct>>=2;
    $lf=$c&03;
    if ($lf==0){
        $lf=1;
    } elsif ($lf==1){
        $lf=2;
    } elsif ($lf==2){
        $lf=4;
    } elsif ($lf==3){
        $lf=0;
    }
    if ($lf){
        read(PGP,$n,$lf);
        $n="\0"x(4-$lf).$n;
	$len=unpack('N',$n);
    } else {
	# This isn't really checked for in most of the handlers.  Perhaps
	# more of them should?
        $len=0;
    }
    return ($ct,$len,$lf);
}

@months=("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep",
	 "Oct","Nov","Dec");
sub date_fmt {
    my($time);
    my($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst);
    # If I'm going to make this available, I might as well avoid
    # the month-first/day-first problem.  'Course, by rights I should
    # do something about the English month-names.  Maybe DD MM YYYY with
    # month in roman numerals (e.g. 15 VII 1993)?  If you feel like it.

    ($time)=@_;
    ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=gmtime($time);
    return(sprintf("%d %s %d  %02d:%02d:%02d",
		   $mday,$months[$mon],$year+1900,$hour,$min,$sec));
}

sub rmpi {
    # read a PGP format Multi-Precision Integer

    my($len,$nlen,$n);
    read(PGP,$len,2);$len=unpack('n',$len);
    $nlen=int($len/8);
    $nlen++ if $len%8;
    read(PGP,$n,$nlen);
    return unpack('H*',$n);
}

sub null_handler {
    # Dummy handler; just skip $len bytes.
    my($len,$dmy);

    ($len)=@_;
    print "(No handler known.  Skipping $len bytes)\n";
    read(PGP,$dmy,$len);
}

sub comment_handler {
    # Just skip $len bytes.
    # Same as above, minus the message.  Both are included for modularity.
    my($len,$dmy);

    ($len)=@_;
    print "$len bytes of comment.\n";
    read(PGP,$dmy,$len);
}

sub uid_handler {
    my($len,$uid);
    
    ($len)=@_;
    read (PGP,$uid,$len);
    print "User ID:\t\"$uid\"\n";
}

sub pub_handler {
    my($len,$vb,$ts,$valid,$alg,$ee,$nn);

    ($len)=@_;
    read(PGP,$vb,1); $len--; $vb=unpack('C',$vb);
    read(PGP,$ts,4); $len-=4; $ts=unpack('N',$ts);
    read(PGP,$valid,2); $len-=2; $valid=unpack('n',$valid);
    read(PGP,$alg,1); $len--; $alg=unpack('c',$alg);
    $nn=&rmpi; $len-=length($nn)/2+2;
    $ee=&rmpi; $len-=length($ee)/2+2;
    printf ("Version Byte:\t%d\n",$vb);
    print "Key Created:\t".&date_fmt($ts)."\n";
    print "Valid for",($valid > 0? ":\t $valid days" : "ever"),"\n";
    printf("Algorithm:\t%d (%s)\n",$alg,($alg==1?"RSA":"??"));
    print "N:\t$nn\n";
    print "E:\t$ee\n";
    print "Warning: Length field is $len bytes too large!\n" if $len;
}

sub conv_handler {
    my ($dmy,$len);

    # Yet another "just suck 'em in" handler.
    ($len)=@_;
    print "$len bytes of data...\n";
    read(PGP,$dmy,$len);
}

sub comp_handler {
    my ($dmy,$len);

    ($len)=@_;
    read(PGP,$dmy,1); $len--; $dmy=unpack('C',$dmy);
    printf ("Algorithm:\t%d (%s)\n",$dmy,($dmy==1?"ZIP":"??"));
    if ($len>0) {
	print "$len bytes of data...\n";
	read(PGP,$dmy,$len);
    }
    else {
	# Presumably runs to the end of the file.
	print "And then a mess of data...\n";
	while (!eof(PGP)) {
	    getc(PGP);
	}
    }
}

sub trust_handler {
    my($len,$byte);
    my($work,$ind);

    ($len)=@_;
    read(PGP,$byte,$len);
    $ind='';			# Indent set to null.
    # Three different meanings, depending on previous packet.
    # If the previous packet is neither key nor userID nor signature,
    # set $ind (so we can tell later) and remark.
    if ($lastctb!=$CTB_PUB && $lastctb!=$CTB_SEC && $lastctb!=$CTB_UID &&
	$lastctb!=$CTB_SKE) {
	# If it's not after a permitted type, then show *all* the
	# possible meanings, in a slightly different format.
	print
	    "Corrupt file! Trust packet should follow key, userID, or sig.\n";
	$ind="\t";
    }
    printf("Trust byte: %s\n",unpack("B8",$byte));
    $byte=unpack('C',$byte);
    if ($ind || $lastctb==$CTB_PUB || $lastctb==$CTB_SEC) {
	print "Trust information if previous packet is key:\n" if $ind;
	# If preceding packet is a KEY packet:
	print "${ind}Trust of this key owner:\t";
	$work=$byte&07;
	if ($work==00) {
	    print "Undefined\n";
	}
	elsif ($work==01) {
	    print "Unknown\n";
	}
	elsif ($work==02) {
	    print "Usually do not trust to sign\n";
	}
	elsif ($work==03) {
	    print "(reserved 011)\n";
	}
	elsif ($work==04) {
	    print "(reserved 100)\n";
	}
	elsif ($work==05) {
	    print "Usually trust to sign\n";
	}
	elsif ($work==06) {
	    print "Always trust to sign\n";
	}
	else {
	    print "Present on secret ring.\n";
	}
	$work=$byte&040;
	if ($work) {
	    print "${ind}DISABLED\n";
	}
	else {
	    print "${ind}Enabled\n";
	}
	# Other bits reserved
	$work=$byte&0200;
	if ($work) {
	    print "${ind}Ultimate Trust: Present on secret ring.\n";
	}
    }

    # If preceding packet is UID:
    if ($ind || $lastctb==$CTB_UID) {
	print "Trust information if previous packet is user ID:\n" if $ind;
	$work=$byte&03;
	if ($work==00) {
	    print "${ind}Unknown if this ID belongs to associated key\n";
	}
	elsif ($work==01) {
	    print "${ind}ID not trusted to belong to associated key\n";
	}
	elsif ($work==02) {
	    print 
	       "${ind}Marginal confidence that ID belongs to associated key\n";
	}
	else {
	    print "${ind}Complete trust that key belongs to associated ID\n";
	}
	# Other bits reserved
	$work=$byte&0200;
	if ($work) {
	    print "${ind}Will only warn if this key is used\n";
	}
	else {
	    print "${ind}Will warn and verify before using this key\n";
	}
    }
    if ($ind || $lastctb==$CTB_SKE) {
	# If previous packet is SIG:
	print "Trust information if previous packet is signature:\n" if $ind;
	print "${ind}Trust of the owner of the signing key:\t";
	$work=$byte&07;
	if ($work==00) {
	    print "Undefined\n";
	}
	elsif ($work==01) {
	    print "Unknown\n";
	}
	elsif ($work==02) {
	    print "Usually do not trust to sign\n";
	}
	elsif ($work==03) {
	    print "(reserved 011)\n";
	}
	elsif ($work==04) {
	    print "(reserved 100)\n";
	}
	elsif ($work==05) {
	    print "Usually trust to sign\n";
	}
	elsif ($work==06) {
	    print "Always trust to sign\n";
	}
	else {
	    print "Present on secret ring.\n";
	}
	# Other bits reserved
	$work=$byte&0100;
	if ($work) {
	    print "${ind}Key checking pass has checked this signature\n";
	}
	else {
	    print "${ind}Key checking pass does not trust this signature\n";
	}
	$work=$byte&0200;
	if ($work) {
	    print 
	     "${ind}Contiguous chain of trusted sigs to ultimate one exists\n";
	}
	else {
	    print 
	 "${ind}No contiguous chain of trusted sigs to ultimate one exists\n";
	}
    }
}

sub pke_handler {
    my ($len,$version,$kid,$alg,$dmy);

    ($len)=@_;
    read(PGP,$version,1); $len--;
    $version=unpack('C',$version);
    printf ("Version:\t%d\n",$version);
    read(PGP,$kid,8); $len-=8;
    $kid=unpack('H*',$kid);
    print "Key ID:\t$kid\n";
    read(PGP,$alg,1); $len--;
    $alg=unpack('C',$alg);
    printf ("Algorithm:\t%d (%s)\n",$alg,(1==$alg ? "RSA" : "??"));
    $dmy=&rmpi;
    print length($dmy)/2, " bytes of data.\n";
    $len-=length($dmy)/2+2;	# add two bytes for length field
    # Yes, I know it will print -123 bytes too long if it's too short.
    print "Warning! length field is $len bytes too long!\n" if $len;
}

sub ske_handler {
    my ($len,$vb,$md5len,$class,$ts,$kid,$pkalg,$digalg,$chk,$dmy);

    ($len)=@_;
    read(PGP,$vb,1); $len--; $vb=unpack('C',$vb);
    printf("Version:\t%d\n",$vb);
    read(PGP,$md5len,1); $len--; $md5len=unpack('C',$md5len);
    printf("Adding %d bytes of header to digest\n",$md5len);
    read(PGP,$class,1); $len--; $class=unpack('C',$class);
    if ($class==0x0) {
	print "Signature of binary document\n";
    }
    elsif ($class==0x1) {
	print "Signature of canonical text document\n";
    }
    elsif ($class==0x10) {
	print "Generic Key certification\n";
    }
    # Most of these are unsupported
    elsif ($class==0x11) {
	print "Persona Key certification (unsupported)\n";
    }
    elsif ($class==0x12) {
	print "Casual ID Key certification (unsupported)\n";
    }
    elsif ($class==0x13) {
	print "Positive ID Key certification (unsupported)\n";
    }
    elsif ($class==0x20) {
	print "Key Compromise certificate, revoking public key\n";
    }
    elsif ($class==0x30) {
	print "Key/UserID Revocation certificate (unsupported)\n";
    }
    elsif ($class==0x40) {
	print "Timestamp of signature (unsupported)\n";
    }
    else {
	printf("Unknown signature classification (%x)\n",$class);
    }
    read(PGP,$ts,4); $len-=4; $ts=unpack('N',$ts);
    print "Signature Created:\t".&date_fmt($ts)."\n";
    read(PGP,$kid,8); $len-=8; $kid=unpack("H*",$kid);
    print "Signing Key ID:\t$kid\n";
    read(PGP,$pkalg,1); $len--; $pkalg=unpack('C',$pkalg);
    printf("Public Key Algorithm:\t%d (%s)\n",
	   $pkalg,($pkalg==1?"RSA":"??"));
    read(PGP,$digalg,1); $len--; $digalg=unpack('C',$digalg);
    printf("Message Digest Algorithm:\t%d (%s)\n",
	   $digalg,($digalg==1?"MD5":"??"));
    read(PGP,$chk,2); $len-=2; $chk=unpack('H*',$chk);
    print "Check bytes:\t$chk\n";
    $dmy=&rmpi;
    print length($dmy)/2, " bytes of data\n";
    $len-=length($dmy)/2+2;	# Add two for bitcount field
    print "Warning!  Length field is $len bytes too long!\n" if $len;
}

sub sec_handler {
    my($len,$vb,$ts,$valid,$alg,$nn,$ee,$ciph,$iv,$dd,$pp,$qq,$uu,
       $chksum);

    ($len)=@_;
    read(PGP,$vb,1); $len--; $vb=unpack('C',$vb);
    print "Version Byte:\t$vb\n";
    read(PGP,$ts,4); $len-=4; $ts=unpack('N',$ts);
    print "Key Created:\t".&date_fmt($ts)."\n";
    read(PGP,$valid,2); $len-=2; $valid=unpack('n',$valid);
    printf("Valid for%s\n",($valid?"\t$valid days":"ever"));
    read(PGP,$alg,1); $len--; $alg=unpack('C',$alg);
    printf("Algorithm:\t%d (%s)\n",$alg,(1==$alg?"RSA":"??"));
    $nn=&rmpi; $len-=length($nn)/2+2;
    print "N:\t$nn\n";
    $ee=&rmpi; $len-=length($ee)/2+2;
    print "E:\t$ee\n";
    read(PGP,$ciph,1); $len--; $ciph=unpack('C',$ciph);
    printf("Protection Algorithm:\t%d (%s)\n",$ciph,
	   ($ciph ? (1==$ciph ? "IDEA" : "??") : "None"));
    if ($ciph) {
	read(PGP,$iv,8); $len-=8;
	print "8 bytes of cipher feedback\n";
    }
    # I don't REALLY need to store all these values, especially since
    # I don't even print them out.  But they're there in case you
    # want to.
    $dd=&rmpi; $len-=length($dd)/2+2;
    print length($dd)/2, " bytes of d\n";
    $pp=&rmpi; $len-=length($pp)/2+2;
    print length($pp)/2, " bytes of p\n";
    $qq=&rmpi; $len-=length($qq)/2+2;
    print length($qq)/2, " bytes of q\n";
    $uu=&rmpi; $len-=length($uu)/2+2;
    print length($uu)/2, " bytes of u\n";
    read(PGP,$chksum,2); $len-=2; $chksum=unpack('H*',$chksum);
    print "Checksum:\t$chksum\n";
    print "Warning!  Length field is $len bytes too long!\n" if $len;
}
        
sub raw_handler {
    my($len,$mode,$namelen,$name,$ts,$data);

    ($len)=@_;
    read(PGP,$mode,1); $len--;
    # There's also 'l'ocal mode, undocumented.
    printf("Mode:\t%s (%s)\n",$mode,
	   ('b' eq $mode ? "binary" : ('t' eq $mode ? "canonical text" :
				       "unknown")));
    read(PGP,$namelen,1); $len--; $namelen=unpack('C',$namelen);
    print "Length of filename:\t$namelen\n";
    read(PGP,$name,$namelen); $len-=$namelen;
    print "Filename:\t$name\n";
    read(PGP,$ts,4); $len-=4; $ts=unpack('N',$ts);
    if ($ts) {
	print "Timestamp:\t".&date_fmt($ts)."\n";
    }
    else {
	# Timestamp can be (and often is) zero, which may mean
	# whatever, but certainly doesn't mean it was created
	# 1 Jan 1970.  Better just to say it's zero.
	print "Timestamp:\tZero\n";
    }
    if ($len>0) {
	read(PGP,$data,$len);
	print "$len bytes of data.\n";
    }
    else {
	print "And then a mess of data...\n";
	while (!eof(PGP)) {
	    getc(PGP);
	}
    }
}

sub process_packet {
    my($ct,$lf,$len,$typestr,$handler);

    return 0 unless (($ct,$len,$lf)=&ctb);
    if ($ct==$CTB_PKE) {
	$typestr="Public-Key Encrypted Packet";
	$handler=\&pke_handler;
    }
    elsif ($ct==$CTB_SKE) {
	$typestr="Secret-Key Encrypted Packet (signature)";
	$handler=\&ske_handler;
    }
    elsif ($ct==$CTB_SEC) {
	$typestr="Secret Key Packet";
	$handler=\&sec_handler;
    }
    elsif ($ct==$CTB_PUB) {
	$typestr="Public Key Packet";
	$handler=\&pub_handler;
    }
    elsif ($ct==$CTB_COMP) {
	$typestr="Compressed Data Packet";
	$handler=\&comp_handler;
    }
    elsif ($ct==$CTB_CKE) {
	$typestr="Conventionally Encrypted Packet";
	$handler=\&conv_handler;
    }
    elsif ($ct==$CTB_RAW) {
	$typestr="Raw Data Packet";
	$handler=\&raw_handler;
    }
    elsif ($ct==$CTB_TRUST) {
	$typestr="Keyring Trust Packet";
	$handler=\&trust_handler;
    }
    elsif ($ct==$CTB_UID) {
	$typestr="User ID Packet";
	$handler=\&uid_handler;
    }
    elsif ($ct==$CTB_CMT) {
	$typestr=="Comment Packet";
	$handler=\&comment_handler;
    }
    else {
	$typestr=sprintf("UNKNOWN PACKET!! (%o)",$ct);
	$handler=\&null_handler;
    }
    print "\n---------------------------\nPacket Type:\t$typestr\n";
    print "Length:\t$len\n";
    &$handler($len);
    $lastctb=$ct;
    return(1);
}

die "Usage: $0 pgpfile" unless @ARGV;
die "Couldn't open $ARGV[0]" unless open(PGP,$ARGV[0]);
$lastctb=0;			# Last seen ctb;
while (1) {
    last unless &process_packet;
}
