#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
require Vyatta::Snort::Config;

# writes the ips config file and exits with proper status:
#   0: success, something changed
#   1: not configured
#   2: failed (error message already displayed)
#   3: success, nothing changed

my $FILE_SNORT_CONF = '/etc/snort/ips.conf';

my $error_prefix = 'IPS configuration error';

my $config = new Vyatta::Snort::Config;
my $oconfig = new Vyatta::Snort::Config;
$config->setup();
$oconfig->setupOrig();

my ($snort_conf, $au_str, $err) = (undef, undef, undef);

# provide config access for auto-updater.
# not part of the snort configuration.
if (defined($ARGV[0]) && $ARGV[0] eq 'get-auto-update') {
  # look at "active" (original)
  ($au_str, $err) = $oconfig->checkAutoUpdate(1);
  print "$au_str";
  exit 0;
}

# check new auto-update config (if any)
($au_str, $err) = $config->checkAutoUpdate(0);
if (defined($err)) {
  # invalid auto-update config
  print "$error_prefix: $err.\n";
  exit 2;
}

if ($config->isEmpty()) {
  # not configured
  exit 1;
}

if (!($config->isDifferentFrom($oconfig))) {
  # config not changed. do nothing.
  exit 3;
}

while (1) {
  ($snort_conf, $err) = $config->get_snort_conf();
  last if (defined($err));
  
  $err = $config->checkQueue();
  last if (defined($err));
  
  # remove everything between markers
  $err = $config->removeCfg($FILE_SNORT_CONF);
  last if (defined($err));
  
  # insert new lines between markers
  $err = $config->writeCfg($FILE_SNORT_CONF, $snort_conf);
  last;
}

if (defined($err)) {
  # failed
  print "$error_prefix: $err.\n";
  exit 2;
}

exit 0;

