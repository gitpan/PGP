package PGP;

require 5.000;

use Carp;
use File::Basename;
use IPC::Open3;
use Time::Local;
use Dumper;

# $debug = 1;

=over 4

=head1 NAME

PGP - perl module to work with PGP messages

=head1 SYNOPSIS

use PGP;

$message = new PGP $pgppath;

=head1 DESCRIPTION

The PGP module allow a perl script to work with PGP related files.

=cut

# $Log: PGP.pm,v $
# Revision 0.1  1996/01/10  02:22:18  hickey
# Initial alpha release
#

$VERSION = '$Id: PGP.pm,v 0.1 1996/01/10 02:22:18 hickey Exp hickey $';

=item * PGP::new

	$pgp = new PGP [$pgppath], [$pgpexec];

Create the PGP encapsulation object. The standard location for the 
PGP executable is /usr/local/bin/pgp.

=cut

sub new
{
  my $class = shift;
  my $pgppath = shift || "$ENV{HOME}/.pgp";
  my $pgpexec = shift || "/usr/local/bin/pgp";
  		 
  if (! -e "$pgppath/config.txt" &&
      ! -e "/usr/local/lib/pgp/config.txt" )
  {
    carp "PGP configuration file not found.";
    return (0);
  };
     
  $self = {     PGPPATH         =>      $pgppath,
  		PGPexec		=>	$pgpexec
          };
          
  bless $self, $class;
}


sub Debug
{
  my (@args) = @_;

  return if (! defined $PGP::debug);

  print STDERR @args, "\n";
}


=item * PGP::Exec

	$pid = Exec $pgp $args, $in, $out, $err;

Execute the PGP command and attach the C<$in>, C<$out>, C<$err> file handles. 
This should be fine for the moment, but need to look into making
sure that data is not written to a temporary file anywhere.

The $args variable can have several substituted strings:

	%p	PGP path variable
	%r	Path to PGP keyring
	%k	Specified user

The file handle variables--C<$in>, C<$out> and C<$err>--are send as
normal filehandle names, but they reside in the PGP package. For
example, the following procedure call is made:

	PGP->Exec ($args, FIN, FOUT, FERR);

Even though the file handles were specified as C<FIN>, C<FOUT> and
C<FERR>; they must be referred to as C<PGP::FIN>, C<PGP::FOUT> and
C<PGP::FERR> in the orignal procedure that made the call.

=cut


sub Exec
{
  my ($self, $args, $in, $out, $err) = @_;
  my ($pgppath, $pgpcmd, $baseopts);

  $baseopts = '+force +batchmode +verbose=1';
  
  # Variable substitutions
  $args =~ s/%p/$self->{PGPPATH}/g;
  $args =~ s/%r/$self->{PGPPATH}\/$self->{Keyring}/g;   # PGP::Keyring
  $args =~ s/%k/0x$self->{Keyid}/g;			# PGP::Key

  Debug ("PGP::Exec=$self->{PGPexec} $baseopts $args");
  $result = open3 ($in, $out, $err, "$self->{PGPexec} $baseopts $args") || croak "PGP command error";
}


=item * PGP::Sign

	$signed_document = Sign $pgp %args;

The C<Sign> procedure will take a file or data and sign with a PGP
secret key. The default behavior is to sign the data with the last
secret key added to the keyring, but that can be overridden with the
I<Key> argument. This method always returns the signed document.

The C<%args> consist of a series of keys and values. Since there are
several variations in the way data can be signed, not all the
following options must be specified. This approach also makes it much
easier to scale to new versions of PGP with more options.

	Armor		The output should be ASCII armored
	Clear		Produce a "clear" signature
	Encrypt		Encrypt the resulting signed document with
			the given keyobj
	Detach		Create a detached signature
	File		Sign the specified file
	Key		Sign with the specified key object
	Nosave		Do not allow user to save message
	Password	The password to use for signing
	Signfile	The filename of the signed document
	Text		Data to be signed.
	Wipe		Remove the orignal file

The only absolute argument that is always required is the C<Password>. 

B<Examples>

 Sign $pgp Password => 'xyz', File => '/etc/motd', Clear => 1, Armor => 1;

This would return a signed copy of the F</etc/motd> file. In this
case, we use a file as the input, but the output is returned at the
method's termination. The orignal file remains in the clear, and the
signature is ASCII armored (Base64). 

 Sign $pgp Password => 'abc', Text => 'Important info', Armor => 1,
           Signfile => 'signed.asc', Key => $keyobj;

This is sort of the reverse of the first example. It takes what is in
the C<Text> field and signs it. It then puts the result in the file
F<signed.asc> and returns it to the caller. In this case, the entire
message is ASCII armored including the orignal text (i.e. C<Text>).
We also specify another secret key to produce the signature. For more
information on the the key objects, please see L<"PGP::Key"> section.

=cut


sub Sign
{
  my ($self, %args) = @_;
  local ($options, $key, $document);
  		    
  Debug ("PGP::Sign Args=", Dumper \%args);

  $options = '-f -s';
  $options .= 'a' if ($args{Armor} == 1);
  $options .= 'b' if ($args{Detach} == 1);
  $options .= 't' if (exists $args{Clear});
  $options .= 'w' if ($args{Wipe} == 1);
  $options .= 'm' if ($args{Nosave} == 1);

  # setup of encryption if we are doing any
  if (defined $args{Encrypt})
  {
    $options .= 'e'; 
    foreach $key (@{$args{Encrypt}})
    {
      $options .= " 0x$key->{Keyid}";
    };
  };
  
  # When signing a document, we always have a password.
  $options .= " -z $args{Password}";

  Debug ("PGP::Sign Options=$options");

  # procede to send the document to PGP.
  $self->Exec ($options, FIN, FOUT, FERR);

  if ($args{File})
  {
    open (PLAIN, "< $args{File}") || carp "$args{File} not found";
    print FIN <PLAIN>;
    close (PLAIN);
  } else
  {
    print FIN $args{Text};
  };
  close (FIN);

  $document = join ('', <FOUT>);

  if ($args{Signfile})
  {
    open (SIGN, "> $args{Signfile}") || carp "Can not create $args{Signfile}";
    print SIGN $document;
    close (SIGN);
  };

  return ($document);
}


=item * PGP::Encrypt

	$encrypted_document = Encrypt $pgp %args;

The C<Encrypt> method produces an encrypted document with the given
public keys specified by C<Key>. The C<Encrypt> method follow the
same conventions as the C<Sign> method. The data to be encrypted can
be sent to the method or can reside in a file. The resulting
encrypted data can also reside in a file or be sent back to the caller. 

In addition to encrypting a document, the document can also be signed
by using the C<Sign> key in the C<%args> array. If the document is to
be signed by the default secret key (last key added to the secret
keyring), then C<Sign> can be left undefined or contain something
other than a reference to a key object. Otherwise the C<Sign> key
should contain a reference to a specific key object (see
L<"PGP::Key">).

	Armor		The output should be ASCII armored
	Encryptfile	The filename of the encrypted document
	File		Encrypt the specified file
	Key		Encrypt with the specified key object
	Nosave		Do not allow user to save message
	Password	The password to use for signing
	Sign		In addition to encrypting, sign the document
	Text		Data to be encrypted
	Wipe		Remove orignal file

=cut


sub Encrypt
{
  my ($self, %args) = @_;
  local ($options, $document, $key, @keys);
  		    
  Debug ("PGP::Encrypt Args=", Dumper \%args);

  $options = '-f -e';
  $options .= 'a' if ($args{Armor} == 1);
  $options .= 's' if (exists $args{Sign});
  $options .= 'w' if ($args{Wipe} == 1);
  $options .= 'm' if ($args{Nosave} == 1);

  # process the Key variable
  if (ref $args{Key} eq 'ARRAY')
  {
    foreach $key (@keys)
    {		     
      $options .= " 0x$key->{Keyid}";
    };
  } 
  else
  {
    $options .= " 0x$args{Key}->{Keyid}";
  };

  # If we are also signing, we need to tell which key and password.
  $options .= " -u 0x$args{Sign}->{Keyid}" if (defined $args{Sign}->{Keyid});
  $options .= " -z $args{Password}" if (defined $args{Password});

  Debug ("PGP::Encrypt Options=$options");

  # procede to send the document to PGP.
  $self->Exec ($options, FIN, FOUT, FERR);

  if ($args{File})
  {
    open (PLAIN, "< $args{File}") || carp "$args{File} not found";
    print FIN <PLAIN>;
    close (PLAIN);
  } else
  {
    print FIN $args{Text};
  };
  close (FIN);

  $document = join ('', <FOUT>);

  if ($args{Encryptfile})
  {
    open (ENCRYPT, "> $args{Encryptfile}") || carp "Can not create $args{Encryptfile}";
    print ENCRYPT $document;
    close (ENCRYPT);
  };

  return ($document);
}

	       
=item * PGP::Decrypt

	\%stats = Decrypt $pgp %args;

C<Decrypt> will use a PGP secret key to decrypt a message. The secret
key must reside on the secret keyring. The C<Decrypt> method follows
the same conventions for data transfer that C<Sign> and C<Encrypt>
follow. The resulting associative array that is sent back contains
three fields:

	Text		The decrypted document
	Signature	PGP::Key object of the signer (if any)
	Time		Time document was signed (if any)
	Key		PGP::Key object used to decrypt document 

The following are the accepted arguments:

	Password	Password to use for decrypting
	File		File to decrypt
	Keyring		Needed to return info about document
	Plainfile	File to put the data in
	Text		Document to decrypt
	Wipe		Remove original file

The C<Password> argument is required to perform the decryption of the
document. The C<Keyring> argument is also required if any document 
information is to be returned.

=cut


sub Decrypt
{
  my ($self, %args) = @_;
  local ($options, $document, $key, @keys);
  		    
  Debug ("PGP::Decrypt Args=", Dumper \%args);

  $options = "-f -z $args{Password}";

  Debug ("PGP::Decrypt Options=$options");

  # procede to send the document to PGP.
  $self->Exec ($options, FIN, FOUT, FERR);

  if ($args{File})
  {
    open (ENCRYPT, "< $args{File}") || carp "$args{File} not found";
    print FIN <ENCRYPT>;
    close (ENCRYPT);
  } else
  {
    print FIN $args{Text};
  };
  close (FIN);

  $document = join ('', <FOUT>);

  if ($args{Plainfile})
  {
    open (PLAIN, "> $args{Plainfile}") || carp "Can not create $args{Plainfile}";
    print PLAIN $document;
    close (PLAIN);
  };

  if (defined $args{Keyring})  
  { 
    $keyring = $args{Keyring};
    
    # gather stats on the decrypted document
    while (<FERR>)
    {
      # Encryption fields
      /Key ID (\w+)\,/i && do 
        { $key = Find $keyring  Keyid => $1 };
	
      # Signature fields
      /^Good signature from user "(.+)"/i && do
      	{ $signature = Find $keyring  Owner => $1 };
      /^Signature made (\d+)\/(\d+)\/(\d+) (\d+):(\d+)/ && do
  	{ $time = &timegm (0, $5, $4, $3, $2-1, $1) };
    };  

    return ({
		Text 		=>	$document,
  	     	Signature	=>	$signature,
	     	Time     	=>	$time,
	     	Key      	=>	$key  
	    });
  }
  else
  {
    return ( { Text	=>	$document   } );
  };
}


=item * PGP::Document_Info

	\%doc = Document_Info $pgp %args;

C<Document_Info> returns an associative array or a reference to an
associative array to the caller. This returned structure contains
information about the document that is sent to the C<Document_Info>
method. The returned structure is fairly straight forward:

	Text		The decrypted document
	Signature	PGP::Key object of the signer (if any)
	Time		Time document was signed (if any)
	Key		PGP::Key object used to decrypt document

The C<Document_Info> method currently accepts the following arguments:

	File		File to decrypt
	Text		Document to decrypt
	
At this point, we cheat with the C<Document_Info> method. Basically
we send the document through the C<Decrypt> method and grab the
results. 

=cut


sub Document_Info
{
  my ($self, %args) = @_;

  $info = $self->Decrypt (%args, Plainfile => '/dev/null');

  return ($info);
}



=head2 PGP::Keyring

The C<PGP::Keyring> object is used to perform key management functions. 

=cut

package PGP::Keyring;
@ISA = qw(PGP);


=item * PGP::Keyring::new

	$Keyring = new PGP::Keyring $pgpkeyring;


=cut


sub new 
{   
  my ($class, $keyring) = @_;
  my ($pgp);
   
  $pgp = new PGP;		# inherit the PGP variables
  $self = {	%$pgp,
		Keyring		=>	$keyring,
  		Keys		=>	[],
		Modified	=>	1
	   };

  bless $self, $class;
  
  # Need to update the Keys field so that it is useful.
  $self->List_Keys;
  
  $self;
};


=item * PGP::Keyring::Add_Key

	$signature = Add_Key $Keyring $signature;

Add a signature to the keyring. At this point, there is no error 
checking or verification that the key has been added.

=cut

sub Add_Key
{
  my ($self, $sign) = @_;

  $self->Exec ("-ka -f %r", FIN, FOUT, FERR);
  print FIN $sign;
  close FIN;
  
  $self->{Modified}++;
}
      

=item * PGP::Remove_Key

	Remove_Key $Keyring $key;

Remove a signature from a keyring.   

=cut


sub Remove_Key
{ 
  my ($self, $key) = @_;
  
  $self->Exec ("-kr -f 0x$key->{Keyid} %r", FIN, FOUT, FERR);
  							   
  $self->{Modified}++;
}


=item * PGP::Extract_Key

	$key = Extract_Key $Keyring $keyobj;

Extract a key from the specified keyring. A real simple dirty way of 
extracting the key.

=cut
 

sub Extract_Key
{
  my ($self, $key) = @_;
  
  $self->Exec ("-kxa -f 0x$key->{Keyid} %r", FIN, FOUT, FERR);
  
  @key = <PGP::FOUT>;
  return (join ('', @key));
}


=item * PGP::Generate_Key

	Generate_Key $Keyring;

Generate a new secret and public key set. This routine will not be
present in the first rev of code. It is also subject to change.

=cut
 

sub Generate_Key
{
  my ($self) = shift;
  
  $self->{Modified}++;
}


=item * PGP::Revoke_Key

	$certificate = Revoke_Key $Keyring $Keyobj;

Produce a revocation certificate for the given key. Revocation is
actually a two step process. We must first mark the key as revoked.
This is the same as the C<Remove_Key> method. After flaging the key,
the key must be extracted to produce a revocation certificate.

=cut

sub Revoke_Key
{
  my ($self, $key) = @_;
  							      
  $self->Remove_Key ($key);
  return ($self->Extract_Key ($key));
}
    
	     
=item * PGP::Keyring::List_Keys

	@{$keyobj} = List_Keys $Keyring;

List the keys on a given keyring. This routine simply captures the output
of the command C<pgp -kc $keyring> and does a quick parse on it. It 
takes the lines that it parses, and constructs L<PGP::Key> objects.
In the near future, this function will also pass the trust factors to the 
PGP::Key object. We got it in the output, so why not use it.

=cut
 

sub List_Keys
{
  my ($self) = @_;
  my ($keyid, $trust, $validity, $desc);
  
  # do not call PGP if the keys have not been modified                                               
  if (!$self->{Modified})                
  { 
    return (wantarray ? @{$self->{Keys}} : $self->{Keys});
  };
  
  $self->Exec ("-kc %r", FIN, FOUT, FERR);  
  	    
  while (<PGP::FOUT>)
  {
    # public key entry
    /^pub/ && do 
      { push (@{$self->{Keys}}, PGP::Key->new ($_)) };
    # more IDs to current key?
    /^\w+(.+)$/ && do 
      { $self->{Keys}->[$#{$self->{Keys}}]->AddID ($1) };
      
    # public key trust entries follow
    last if (/^\s+KeyID\s+Trust\s+Validity\s+User ID/);  
  };
	      
  while (<PGP::FOUT>)
  { 
    # valid entry?		   
    /^..(\w+)\s+(\w+)\s+(\w+)\s+(.+)/ && do 
    { 
      $keyid = $1; $trust = $2; $validity = $3; $desc = $4;
      $key = Find $self Keyid => $keyid;
      
      $key->Trust ($trust);
      $key->Validity ($validity);
    };
  };

  # Now that we have the latest keyring data, reset the modified flag
  undef $self->{Modified};
    
  return (wantarray ? @{$self->{Keys}} : $self->{Keys});  
}


=item * PGP::Keyring::Find

	@keys = Find $keyring %criteria;
	\@keys = Find $keyring %criteria;
	$key = Find $keyring %criteria; (Single match)

Function to locate a single key.

=cut 


sub Find
{
  my ($self, %criteria) = @_;
  my ($key, @match, $crit);
  
  NONMATCH:
  foreach $key (@{$self->{Keys}})
  {		     		
    foreach $crit (keys %criteria)
    {
      if (ref ($key->{$crit}) ne 'ARRAY')
        { next NONMATCH if ($key->{$crit} !~ /$criteria{$crit}/i) }
       else 
        {
	  for ($[ .. $#{$key->{$crit}})
	  { next NONMATCH if ($key->{$crit}->[$_] !~ /$criteria{$crit}/i) };
	};
    };
    push (@match, $key);
  };
  
  return ($match[$[]) if ($#match == 0);
  return (wantarray ? @match : \@match);
}  
  	     



package PGP::Key;
@ISA = qw(PGP);

	   
use Time::Local;


=head2 PGP::Key

The C<PGP::Key> object is used to store the individual key
information. It is primarily used by the C<PGP::Keyring> object and
for passing to the various methods that accept key parameters to
encrypt and sign documents. 

Future revisions will provide actual methods to do key comparison for
the trust and validity factors. These methods will provide a
standardized way to determine which keys can be trusted and which
keys should not be used at all.

=cut 

=item * PGP::Key::new

	$key = new PGP::Key $keyline;

This is the constructor for the C<PGP::Key> object. This is primarily
used by the C<PGP::Keyring> methods. The C<PGP::Keyring> methods keep
track of the keys and maintain the Trust and Validity components.
About the only useful method is the C<PGP::Key::Fingerprint>, which
will return a string that is the finger print of the given key.

=cut

sub new
{
  my ($class, $keyline) = @_;
  my ($bits, $keyid, $date, $owner, $pgp);
  
  chomp $key;
  ($bits, $keyid, $date, $owner) = &keyparse ($keyline);
  			    
  $pgp = new PGP;		# inherit the PGP variables
  $self = { %$pgp,
	    Bits	=>	$bits,
  	    Keyid	=>	$keyid,
	    Date	=>	$date
	  };	       		     

  bless $self, $class;		  
  	
  # Add on the ID information to the key object
  $self->Add_ID ($desc);
  
  $self; 
}


=item + PGP::Key::Add_ID

	Add_ID $key $desc;

The C<Add_ID> method will add identification information to the owner 
and email portions of the given C<PGP::Key> object. This is to support 
keys that multiple identification packets associated with them.

=cut		       
					  
sub Add_ID
{
  my ($self, $desc) = @_;
  					       
  # we have a total of three types of entries for the description
  #	full name <email@domain>        /\<.+\>/
  #	email@domain			/[\w\.\-\+]@[\w\.\-\+]/
  #	full name			all other 
  
  if ($desc =~ /\<.+\>/)
  {
    $desc =~ /([^\<]+)\s+\<(.+)\>/;
    push (@{$self->{Owner}}, $1);
    push (@{$self->{Email}}, $2);
  }
  elsif ($desc =~ /[\w\.\-\+]@[\w\.\-\+]/)
    {
      push (@{$self->{Owner}}, undef);
      push (@{$self->{Email}}, $desc);
    }
    else
      {
        push (@{$self->{Owner}}, $desc);
        push (@{$self->{Email}}, undef);
      };
}

	      
sub keyparse
{
  my ($keyline) = shift;
  my ($bits, $keyid, $yr, $mon, $day, $desc);
			
  ($bits, $keyid, $yr, $mon, $day, $desc) = 
      ($keyline =~ /^pub\s+(\d+)\/(\w+)\s+(\d+)\/(\d+)\/(\d+)\s+(.+)$/);
 
  $date = &timegm (0, 0, 0, $day, $--mon, $year);
  				     
  return ($bits, $keyid, $date, $desc);
}
				 


=item * PGP::Key::Trust

This will set and/or retrieve the trust factor. Currently, this routine
will just store what is sent to it. Need to define some "trust" 
variables and provide useful routines to use them.

=cut


sub Trust
{
  my ($self, $trust) = @_;
  
  $self->{Trust} = $trust if ($trust);
  $self->{Trust};
}


=item * PGP::Key::Validity

This function will set and/or return the validity factor. This 
subroutine is very much like PGP::Key::Trust. It also needs to be 
worked on quite a bit.

=cut
     

sub Validity
{
  my ($self, $validity) = @_;
  
  $self->{Validity} = $validity if ($validity);
  $self->{Validity};
}


=item * PGP::Key::Fingerprint

	$fingerprint = Fingerprint $key;


=cut

# does the Fingerprint method belong in the key management stuff?

sub Fingerprint
{
  my ($self) = shift;

  $self->Exec ("-kvc", FIN, FOUT, FERR);

  while (<FOUT>)
  {
    /Key fingerprint = (.+)[\n\r]$/ && do 
	{ $fingerprint = $1 };
  };
  
  return $fingerprint;
};

			      
sub dump
{
  my $self = shift;
  
  print "Key: ", $self->{Keyid}, " :: ", $self->{Owner}, " <", $self->{Email}, ">\n";
  print "\tSize: ", $self->{Bits}, "\tTrust: ", $self->{Trust};
  print "\t\tValidity: ", $self->{Validity}, "\n";
}

=head2 Known Bugs and Limitations

=item + Hopefully none, proabably many!

=head2 Author

	Gerard Hickey
	RR 2  Box 409
	Lower Main St.
	North Berwick, ME   03906
	hickey@ctron.com

=head2 Copyrights

	Copyleft (l) 1996, by Gerard Hickey

What this means is that this program may be copied freely given that
there is no payment in exchange for this program, and that all the
source is left intact with all comments and documentation. If you
wish to modify this program to correct bugs or to extend it's
usefullness, please coordinate such actions with the author.

=cut

