package PGP;
$VERSION = 1.0;

=head1 NAME

PGP - interfaces for signing and authenticating documents using PGP 2.6.2

=head1 SYNOPSIS

    use PGP;

    PGP::setpassword("mary had a little lamb");
    $signed_text = PGP::sign($text);
    ($signer, $text) = PGP::unsign($signed_text);

=head1 DESCRIPTION

These three functions are the first shaky steps towards an actual PGP
implementation.  sign() uses the password set via set_PGP_password
to implement digital signing using the running user's default signature.
If the signing process fails, $signed_text is null. 

Authenticate determines who the signer is from the signed text, iff the
running user has her public key.  If she doesn't, $signer is null.

=head1 NOTES

=head2 This is Not Finished Software

As of Wed Jan  3 15:28:39 CST 1996, This module implements only what I
need to get work done on Penguin.pm.  I don't plan on extending it further.

=head2 Understand the Security Implications Before You Use This

I don't make any representations about this code being secure.  Over
time, as the net beats on it, I expect it to become mostly secure.
However, right now, it's not as secure as PGP is (it writes your secret
password in the clear to a temp file, it keeps it in the clear in memory,
and it doesn't scrub the password off the disk six times).

=head2 Contact

I'm fsg\@coriolan.amicus.com.  I love getting e-mail.  Especially if
it extends or replaces huge chunks of my code.

=cut

sub bootstrap {

    srand($$|time); # used in tmpnam

    if ($ENV{'PGP'}) {
        $PGP::executable = $ENV{'PGP'};
    } elsif (-x "/usr/local/bin/pgp") {
        $PGP::executable = "/usr/local/bin/pgp";
    } elsif (-x "/usr/bin/pgp") {
        $PGP::executable = "/usr/bin/pgp";
    } else {
        die("Couldn't locate needed PGP executable in environment, " .
             "/usr/local/bin or /usr/bin");
    }
    
    $PGP::secretpassword = $PGP::secretpassword || $ENV{'PGPPASS'} ||
          die "Can't unlock your private key, don't have the password";
        
    # note: it's best to have TMP be a really secure personal
    # temporary directory, rather than a world-writable one, to
    # defend against symbolic link and race condition attacks.

    $PGP::TMP = $ENV{'TMPDIR'} || $ENV{'TMP'} || "/tmp";
    $PGP::bootstrapped = 1;
}

sub sign {
    $PGP::bootstrapped or &PGP::bootstrap;

    my $document = shift;
    my $tempfilename = &PGP::tmpnam;
    my $savedslash = $/;

    umask(0077); # fairly-securize permissions
    unlink($tempfilename); # removes at least one attack method

    open(TEMPFILE, ">${tempfilename}") ||
           die("sign couldn't write to temporary file ${tempfilename}!");
    print TEMPFILE "${PGP::secretpassword}\n";
    print TEMPFILE $document;
    close(TEMPFILE);
    # RACE CONDITION ALERT: WE HAVE THE USER'S PLAINTEXT PASSWORD
    # IN A FILE RIGHT NOW

    $ENV{'PGPPASSFD'} = '0'; # see pgp2.6.2 source code; this has the
                             # effect of using the first line of the
                             # input as the secret password.

    # the following system call is okay, since we constructed $tempfilename
    # from non-tainted sources.

    system("${PGP::executable} -fas < ${tempfilename} >& /dev/null > ${tempfilename}.pgp"); 
    # system("${PGP::executable} -asf < ${tempfilename} > ${tempfilename}.pgp"); 

    # should really check the stderr for actual errors.  As it turns out,
    # the stdout is zero on error anyway, which is what we want.

    unlink(${tempfilename}) ||
        die("couldn't unlink the cleartext temporary file ${tempfilename}!");
    # END OF RACE CONDITION ALERT

    open(PGPRESULTS, "<${tempfilename}.pgp") || die;

    $/ = undef;
    $results = <PGPRESULTS>;
    $/ = $savedslash;
    close(PGPRESULTS);

    # I can't think of a reason why the manence of a signed file would
    # be a security problem, but we might as well be paranoid.

    unlink("${tempfilename}.pgp") ||
       die("couldn't unlink the signed temporary file ${tempfilename}.pgp!");

    $results;
}

sub unsign {
    $PGP::bootstrapped or &PGP::bootstrap;
    my $document = shift;
    my $temperrname = &tmpnam;
    my $tempoutname = &tmpnam;
    my $filelines;
    my $savedslash = $/;

    $ENV{'PGPPASSFD'} = "";
    open(WRITETOPGP, "| pgp -f >& ${temperrname} > ${tempoutname}") || die;
    print WRITETOPGP $document;
    close(WRITETOPGP);

    open(TEMPERR, "<${temperrname}") || die("couldn't open PGP stderr file " .
                                            $temperrname);
    undef($/);
    $filelines = <TEMPERR>;
    close(TEMPERR);
    unlink($temperrname);

    if ($filelines =~ /\nGood signature from user "(.*?)"/) {
        $username = $1;
    } else {
        $username = ""; # unknown signee
    }

    open(TEMPOUT, "<${tempoutname}") || die("couldn't open PGP stdout file " .
                                          $tempoutname);
    $filelines = <TEMPOUT>;
    close(TEMPOUT);
    unlink($tempoutname);
    $/ = $savedslash;
    return ($username, $filelines);
}

sub setpassword {
    $PGP::secretpassword = shift;
}

sub tmpnam {
    while((-f ($x = $PGP::TMP . "/" . "$$" . time . rand(1000000)))) {
    }
    $x;
}

1;
__END__;

