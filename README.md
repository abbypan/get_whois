# get_whois
extract domain whois to json

# install

    cpan Date::Calc Net::Domain::ExpireDate Net::Whois::Raw JSON

# usage

    perl get_whois.pl [domain]

    $ perl get_whois.pl google.com

    {"is_exist":1,"creation":"1997-09-15","expiration":"2020-09-13",
    "email":"dns-admin@google.com",
    "status":"clientDeleteProhibited,clientTransferProhibited,clientUpdateProhibited,serverDeleteProhibited,serverTransferProhibited,serverUpdateProhibited",
    "registrar":"MarkMonitor, Inc.",
    "ns":"ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"}
