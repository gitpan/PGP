#!/usr/local/bin/perl

use PGP;
use Dumper;

$key = "-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: 2.6.2

mQA9AzCv53AAAAEBgKKbUwkvtfqmPaCVyv+Jqenz+JvODviDWcSdgYm0vzrAi+nc
dvkpcygj5jOTH/R5EQAFEbQEdGVzdA==
=2+K7
-----END PGP PUBLIC KEY BLOCK-----";
		     
$pgp = new PGP '/home/hickey/.pgp';

$ring = new PGP::Keyring 'pubring.pgp', $pgp;
@keys = List_Keys $ring;
 
txt = Decrypt $pgp File => 'tst2.pl.asc', Password => 'asdf',
	Keyring => $ring;

print Dumper $txt;


#$key = Find $ring Owner => 'hickey';

#$txt = Encrypt $pgp File => '/etc/passwd', Armor => 1, 
#	Encryptfile => '/tmp/passwd.pgp', Key => $key;

#print "$txt\n";

#
# foreach $k (@keys)
# {
#   $k->dump;
#   print "\n";
# };

# $key = Extract_Key $ring 'hickey';
# print Dumper $key;
