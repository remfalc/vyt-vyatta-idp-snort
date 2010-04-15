#!/usr/bin/perl
#
# Module: vyatta-get-snort-rules.pl
# 
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2010 Vyatta, Inc.
# All Rights Reserved.
# 
# Author: Stig Thormodsrud
# Date: April 2010
# Description: get new rules from snort.org
# 
# **** End License ****
#

use strict;
use lib "/opt/vyatta/share/perl5";

require Vyatta::Config;

my $rules = $ARGV[0];

my $BASE_DIR                = '/opt/vyatta/etc/ips';
my $LOG_FILE                = "$BASE_DIR/update.log";
my $URL_PREFIX              = 'http://www.snort.org/pub-bin/oinkmaster.cgi';
my $LAST_UPDATE_STATUS_FILE = "$BASE_DIR/lastupdatestatus";
my $CUR_TIME                = `date +%F-%H%M%S`;
my $LAST_DOWNLOAD           = "$BASE_DIR/last_download";


sub log_message {
    my $msg = shift;
    system("echo \"$CUR_TIME: $msg\" >> $LOG_FILE");
}

sub abort_updates {
    my $msg = shift;
    log_message($msg);
    log_message("Update aborted due to error. IPS rules not updated.");
    my $date = `date`;
    system("echo update failed at $date > $LAST_UPDATE_STATUS_FILE");
    exit 1
}

my ($cmd, $ret, $oink, $config, $url);

chomp $CUR_TIME ;
$config = new Vyatta::Config;
$config->setLevel('content-inspection ips auto-update');
$oink = $config->returnOrigValue('oink-code');
if (! defined($oink)) {
    about_updates("No oink code configured.");
}

# snort.org only allows you to download every 15 minutes
my $last_time = undef;
my $now = time();
if (-e $LAST_DOWNLOAD) {
    $last_time = `cat $LAST_DOWNLOAD`;
    chomp $last_time;
}

if (defined $last_time) {
    my $diff = $now - $last_time;
    if ($diff < 15*60) {
        log_message("Too soon to update again. Update $diff seconds ago.");
        exit(1);
    }
} 

system("echo -n $now > $LAST_DOWNLOAD");
$url = "$URL_PREFIX/$oink/$rules";
$cmd = "wget -O /tmp/$rules -q $url";
$ret = system($cmd);
if ($ret) {
    abort_updates("Failed to get $url");
}

exit 0;
