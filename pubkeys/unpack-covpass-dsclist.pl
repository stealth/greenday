#!/usr/bin/perl

use JSON;

my $json = JSON->new();
my $data = "";

for (;<STDIN>;) {
	$data .= $_;
}
$data =~ s/[^{]+//;
my $p = $json->decode($data);
my $i = 0;

foreach my $cert (@{$p->{certificates}}) {
	my $pem = "-----BEGIN CERTIFICATE-----\n".$cert->{rawData}."\n-----END CERTIFICATE-----\n";
	open(P, ">fresh_$i.pem");
	print P $pem;
	close(P);
	system("openssl x509 -text -in fresh_$i.pem -out covpass_dsclist_$i.pem");
	unlink("fresh_$i.pem");
	++$i;
}


