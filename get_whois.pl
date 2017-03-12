#!/usr/bin/perl
use strict;
use warnings;
use utf8;

use Date::Calc qw/Parse_Date Decode_Date_EU Decode_Date_EU Decode_Date_EU2 Decode_Date_US Decode_Date_US2/;
use Net::Domain::ExpireDate;
use Net::Whois::Raw;
use JSON;

$Net::Whois::Raw::OMIT_MSG   = 1;
$Net::Whois::Raw::CHECK_FAIL = 1;
$Net::Whois::Raw::TIMEOUT    = 10;

my $info = get_whois_info( @ARGV );
my $s    = encode_json( $info );
print $s, "\n";

sub get_whois_info {
  my ( $dom ) = @_;

  my $whois_ref = get_whois( $dom, undef, 'QRY_ALL' );
  my @whois_info = reverse grep { $_ } map { trim_whois_info( $_->{text} ) } @$whois_ref;

  my %inf;
  for my $whois ( @whois_info ) {
    $inf{is_exist}   = is_exist_domain( $whois )       || 0;
    $inf{expiration} = parse_expiration_date( $whois ) || '';
    $inf{creation}   = parse_creation_date( $whois )   || '';
    $inf{email}      = parse_email( $whois )           || '';
    $inf{ns}         = parse_ns( $whois )              || '';
    $inf{status}     = parse_status( $whois )          || '';
    $inf{registrar}  = parse_registrar( $whois )       || '';
    last if ( $inf{expiration} and $inf{creation} );
  }

  return \%inf;
} ## end sub get_whois_info

sub trim_whois_info {
  my ( $whois ) = @_;

  for ( $whois ) {
    s/NOTICE AND TERMS OF USE: .+?\n\n/\n/sg;
    s/^\s*\[proxy\]\s+Generic WHOIS Daemon.*//s;
    s/This whois service is provided by CentralNic .*//s;
    s/Registration Service Provider: Network Solutions Inc.*//s;
    s/Whois Server Version[^\n]+//sg;
    s/Domain names in the .com and .net domains can now be registered.*?\n\n//gs;
    s/>>> Last update of whois database: [^\n]+//sg;
    s/Last update of whois database: [^\n]+//sg;
    s/>>>> Whois database was last updated on: .*$//sg;
    s/WHOIS look-?up made at [^\n]+//sg;
    s/\nLast updated on [^\n]+//sg;
    s/\n\s*NOTICE:.+?\n\n/\n/sg;
    s/\n\s*TERMS OF USE:.+?\n\n/\n/sg;
    s/\n\s*友情提示.*//sg;
    s/\n\s*Database last updated on [^\n]+//sg;
    s/Date and Time of Query: [^\n]+//sg;
    s/no matching record//sg;
    s/ [.]{3,}/:/gs;
    s/^%[^\n]+?\(BRST[^\n]+//g;
    s/(^|\n)%[^\n]+(?=\n|$)/\n/gs;
    s/\n{3,}/\n\n/gs;
    s/\s*$//sg;
    s/^\s*//gs;
    s/^.*abide by Network Solutions' WHOIS policy.*//gs;
    s/^.*No match for.*//gis;
    s/^.*No whois server is known for this kind of object.*//gis;
    s/^.*WHOIS LIMIT EXCEEDED.*//gis;
    s/^.*FAILURE TO LOCATE A RECORD IN THE WHOIS DATABASE IS NOT INDICATIVE.*//gis;
    s/^\s*288\s*$//gis;
    s/\t/ /gs;
    s/Database last updated[^\n]+//sg;
    s/Date and Time of Query[^\n]+//sg;
    s/Record Last Modified[^\n]+//sg;
    s/WHOIS look-up made at[^\n]+//sg;
    s/last updated on[^\n]+//sgi;
    s/member\.asp[^\n]+//sg;
    s/YOUR IP address[^\n]+//sgi;
    s#<a href=[^\n]+?</a>##sgi;
    s/For complete domain details go to[^\n]+//sgi;
    s/'/ /gs;
    s/"/ /gs;
    s/^Not Found!$//g;
  } ## end for ( $whois )

  return $whois;
} ## end sub trim_whois_info

sub is_exist_domain {
  my ( $whois ) = @_;
  return 0 unless ( $whois );
  return 0 if ( $whois =~ /Domain not Found/si );
  return 1;
}

sub parse_status {
  my ( $whois ) = @_;

  my @reg = ( qr/Domain Status[:\s]+(.*?\S)(?:\s*\n|\s+.+?\n)/is, );

  my @status = match_regex_list( $whois, \@reg );
  return unless ( @status );
  my $status_list = join( ",", sort { $a cmp $b } @status );
  return $status_list;
}

sub parse_ns {
  my ( $whois ) = @_;

  my @reg = ( qr/Name Server[:\s]+(.*?\S)\s*\n/is, );

  my @ns = match_regex_list( $whois, \@reg );
  return unless ( @ns );
  my $ns_list = join( ",", sort { $a cmp $b } map { s/\.$//; lc } @ns );
  return $ns_list;
}

sub parse_creation_date {
  my ( $whois ) = @_;

  my @reg = ( qr/Creation\s+Date[:\s]+(.*?)\n/is, qr/Created On[:\s]+(.*?)\n/is, qr/Registration Date[:\s]+(.*?)\n/is, );

  my $create = match_regex_list( $whois, \@reg );
  return normalize_date( $create );
}

sub match_regex_list {
  my ( $src, $regex_list ) = @_;
  my $m;
  for my $r ( @$regex_list ) {
    my @matches = $src =~ /$r/g;
    return ( @matches ) if ( @matches and wantarray );
    $m = $matches[-1] if ( @matches );
    return $m if ( $m );
  }
}

sub parse_expiration_date {
  my ( $whois ) = @_;
  my @expires = (
    qr/Domain Expiration Date[:\s]+(.*?)\n/is,
    qr/Expiry Date:\s*(.*?)\n/is,
    qr/Record expires on\s*(.*?)\.\n/is,
    qr/Expiration Date\s*:\s*(.*?)\.?(?:\n|$)/is,
    qr/paid-till:\s*(.*?)\n/is,
    qr/Record expires on:\s*(.*?)\n/is,
    qr/\nexpire:\s*(.*?)\n/is,
    qr/Renewal date:\s*(.*?)\n/is,
    qr/\x{6709}\x{52b9}\x{671f}\x{9650}\]\s*(.*?)\n/is,
  );
  my $expire = match_regex_list( $whois, \@expires );
  eval { $expire = expdate_fmt( $whois ); } unless ( $expire );
  return normalize_date( $expire );
}

sub normalize_date {
  my ( $date ) = @_;
  return '' unless ( $date );

  $date =~ s/\d{2}:\d{2}(:\d{2})?//;
  $date =~ s/[\.\/]\s*/-/g if ( $date =~ /^[\d\.\/]+$/ );
  $date =~ s/\. /-/g;
  $date =~ s/\(YYYY-MM-DD\).*//s;
  return '' unless ( $date );

  my @temp = Parse_Date( $date );
  @temp = Decode_Date_EU( $date )  unless ( @temp );
  @temp = Decode_Date_EU2( $date ) unless ( @temp );
  @temp = Decode_Date_US( $date )  unless ( @temp );
  @temp = Decode_Date_US2( $date ) unless ( @temp );

  $date = sprintf( "%4d-%02d-%02d", @temp ) if ( @temp );
  $date =~ s#TZ?.*$##;
  return $date || '';
} ## end sub normalize_date

sub parse_email {
  my ( $whois ) = @_;
  my @reg = ( qr/Admin Email[:\s]+(.+?)\n/is, );
  my $email = match_regex_list( $whois, \@reg );
  return $email;
}

sub parse_registrar {
  my ( $whois ) = @_;
  my @reg = ( qr/Registrar:\s*(.+?)\n/is, );
  my $registrar = match_regex_list( $whois, \@reg );
  return $registrar;
}
