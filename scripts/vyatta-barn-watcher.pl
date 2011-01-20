#!/usr/bin/perl
#
# Module: vyatta-barn-watcher.pl
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
# Portions created by Vyatta are Copyright (C) 2010-2011 Vyatta, Inc.
# All Rights Reserved.
# 
# Author: Stig Thormodsrud
# Date: December 2010
# Description: call barnyard to process log files
# 
# **** End License ****
#

use Fcntl qw(:flock);
use Sys::Syslog qw(:standard :macros);
use POSIX;
use Getopt::Long;
use Net::Ping;

use lib "/opt/vyatta/share/perl5";
require Vyatta::Config;

use strict;
use warnings;

my $by_daemon = '/usr/bin/barnyard2';
my $by_pid    = '/var/run/barnyard2_NULL.pid';
my $by_conf   = '/etc/snort/barnyard2.conf';
my $by_log    = '/var/log/barnyard2/barn-watcher.log';
my $log_dir   = '/var/log/snort';
my $pattern   = 'snort-unified2.log';

my $lock_file = '/tmp/barn_cron.lock';

sub barn_log {
    my $timestamp = strftime("%Y%m%d-%H:%M.%S", localtime);
    my $fh;
    if (! open($fh, '>>', $by_log)) {
	syslog('err', "Can't open $by_log: $!");
        exit 1;
    }
    print $fh "$timestamp: ", @_ , "\n";
    close $fh;
}

sub is_running {
    my ($pid_file) = @_;

    if (-f $pid_file) {
	my $pid = `cat $pid_file`;
	$pid =~ s/\s+$//;  # chomp doesn't remove nl
	my $ps = `ps -p $pid -o comm=`;
	if (defined($ps) && $ps ne "") {
	    return $pid;
	} 
    }
    return 0;
}

sub check_connectivity {
    my ($host) = @_;

    # at boot-up it could take some time before the remote database
    # is reachable and we don't want to start barnyard2 before
    # it's reachable

    my $p  = Net::Ping->new();
    my $rc = $p->ping($host);
    $p->close();
    return $rc;
}

sub wait_for_connectivity {
    my ($host) = @_;

    return if ! defined $host;
    while (1) {
        return 1 if check_connectivity($host);
        barn_log("connectivity check failed [$host]");
        sleep(30);
    }
}

sub test_barn_config {
    my ($cmd) = @_;

    if (! -e $by_conf) {
        barn_log("Missing conf file");
        exit 1;
    }
    my $rc = system("sudo $cmd -T -q");
    if ($rc) {
        barn_log("conf file test failed");
        exit 1;
    }
    barn_log("conf file ok");
}

sub check_for_error {
    my (@lines) = @_;

    my $error;
    foreach my $line (@lines) {
        if ($line =~ /^ERROR:\s*(.*)$/) {
            $error = $1;
            last;
        }
    }
    return $error;
}

my $not_done = 1;

sub catch_sigint {
    barn_log("catch_sigint");
    my $pid = is_running($by_pid);
    if ($pid > 0) {
        system("sudo kill $pid");
    }
    $not_done = 0;
}

sub catch_sigusr1 {
    barn_log("catch_sigusr1");
    my $pid = is_running($by_pid);
    if ($pid > 0) {
        system("sudo kill $pid");
    }    
}


#
# main
#

my ($pidfile, $ipaddr);
GetOptions('pidfile=s'       => \$pidfile,
           'ipaddr=s'        => \$ipaddr,
);

open(my $lck, '>', $lock_file) || die "Lock failed\n";
flock($lck, LOCK_EX);
openlog($0, "", LOG_USER);

$pidfile = '/var/run/vyatta-barn-watch' if ! defined $pidfile;
open(my $PF, '>', $pidfile) || die "open failed [$pidfile]: $!";
print $PF "$$";
close($PF);

$SIG{INT}  = \&catch_sigint;
$SIG{USR1} = \&catch_sigusr1;
unlink($by_log);

my $cmd = "$by_daemon -c $by_conf -d $log_dir -f $pattern --pid-path /var/run";
do {
    my $rc = wait_for_connectivity($ipaddr);
    barn_log("$ipaddr reachable") if $rc;
    test_barn_config($cmd);
    barn_log("starting barnyard2");
    my @lines = `sudo $cmd 2>&1`;
    my $err = check_for_error(@lines);
    $err = 'sigint' if $not_done == 0;
    $err = 'unknown' if ! $err;
    barn_log("barnyard exit [$err]");
} while ($not_done);
barn_log("quiting");
unlink($pidfile);

close($lck);
exit 0;

#end of file
