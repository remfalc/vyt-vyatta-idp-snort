#!/usr/bin/perl
#
# Module: vyatta-modify-sids.pl
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
# Date: May 2010
# Description: read disable-sids/enable-sids and updates rules
# 
# **** End License ****
#

use Getopt::Long;

use strict;
use warnings;

#
# This script can be called from configuration mode or from the 
# auto-update script.  
#

my $debug = 0;

sub read_sid_file {
    my ($file) = @_;

    my @lines = ();
    if ( -e $file) {
      open(my $FILE, '<', $file) or die "Error: read [$file] $!";
      @lines = <$FILE>;
      close($FILE);
      chomp @lines;
    }
    return @lines;
}

sub write_sid_file {
    my ($file, @lines) = @_;	    

    if (scalar(@lines) > 0) {
      open(my $FILE, '>', $file) or die "Error: write [$file] $!";
      print $FILE join("\n", @lines), "\n";
      close($FILE);
    } else {
      system("rm -f $file");
    }
}

sub add_sid {
    my ($file, $sid) = @_;

    my @lines = read_sid_file($file);
    foreach my $line (@lines) {
        return if $line eq $sid;
    }
    push @lines, $sid;
    write_sid_file($file, @lines);
    return @lines; 
}

sub del_sid {
    my ($file, $sid) = @_;

    my @lines = read_sid_file($file);
    my @new_lines = ();
    foreach my $line (@lines) {
        push @new_lines, $line if $line ne $sid;
    }
    write_sid_file($file, @new_lines) if scalar(@lines) ne scalar(@new_lines);
    return @new_lines;
}

sub update_rules {
    my ($rule_dir, $disable_file, $enable_file) = @_;

    opendir(my $RIN_DIR, "$rule_dir") or die "Cannot open [$rule_dir]: $!";
    my @rule_files = grep /\.rules$/, readdir($RIN_DIR);
    closedir $RIN_DIR;
    
    my @lines = read_sid_file($disable_file);
    my %dsids = map { $_ => 1 } @lines;

    @lines = read_sid_file($enable_file);
    my %esids = map { $_ => 1 } @lines;

    my ($tot, $ok, $disabled, $comments, $err) = (0,0,0,0,0);

    foreach my $file (@rule_files) {
        open(my $RIN, '<', "$rule_dir/$file") or 
            die "Cannot open $rule_dir/$file: $!";
        my $output = '';
        while (<$RIN>) {
            my $line = $_;
            chomp $line;
            $tot++;
            if (/^#?\s*p[1234]action.*sid:(\d+);.*$/) {
                my $sid = $1;
                if (/^#/) {
                    $disabled++;
                    if (defined $dsids{$sid}) {
                        # already disabled
                        $dsids{$sid}++;
                    }
                    if ($esids{$sid}) {
                        $line =~ s/^#\s*(.*)/$1/;
                        $esids{$sid}++;
                    }
                } else {
                    $ok++;
                    if (defined $esids{$sid}) {
                        # already enabled
                        $esids{$sid}++ if defined $esids{$sid};
                    }
                    if ($dsids{$sid}) {
                        $line = "# $line";
                        $dsids{$sid}++;
                    }
                }
            } else {
                if ($line eq '') {
                    # whitespace
                } elsif ($line =~ /^#/) {
                    $comments++;
                } else {
                    $err++;
                    print "Warning: not found [$line] in [$file]\n";
                }
            }
            $output .= "$line\n";
        }
        close $RIN;
        open(my $ROUT, '>', "$rule_dir/$file") or 
            die "Cannot open $rule_dir/$file: $!";
        print $ROUT $output;
        close $ROUT;
    }

    foreach my $sid (sort keys %dsids) {  
        if ($dsids{$sid} == 1) {
            print "Warning: disable-sid [$sid] not found.\n";
        }
    }

    foreach my $sid (sort keys %esids) {  
        if ($esids{$sid} == 1) {
            print "Warning: enable-sid [$sid] not found.\n";
        }
    }
    
    if ($debug) {
        print "\n";
        print "Total line: [$tot]\n";
        print "        ok: [$ok]\n";
        print "  comments: [$comments]\n";
        print "  disabled: [$disabled]\n";
        print "     error: [$err]\n";
    }

    return 0;
}


#
# main
#

my ($action, $rule_dir, $disable_file, $enable_file, $file, $sid);
GetOptions('action=s'       => \$action,
           'ruledir=s'      => \$rule_dir,
           'disablefile=s' => \$disable_file,
           'enablefile=s'   => \$enable_file,
           'file=s'         => \$file,
           'sid=s'          => \$sid,
          );
if (!defined($action)) {
    print "Error: must define action\n";
    exit 1;
}

my $rc = 1;

if ($action eq 'add-sid') {
    if (!defined($file)) {
        print "Error: must define file\n";
        exit 1;
    }    
    if (!defined($sid)) {
        print "Error: must define sid\n";
        exit 1;
    }    

    print "Add sid [$file] [$sid]\n" if $debug;
    add_sid($file, $sid);
    exit 0;
}

if ($action eq 'del-sid') {
    if (!defined($file)) {
        print "Error: must define file\n";
        exit 1;
    }    
    if (!defined($sid)) {
        print "Error: must define sid\n";
        exit 1;
    }    
    print "Del sid [$file] [$sid]\n" if $debug;
    del_sid($file, $sid);
    exit 0;
}

if ($action eq 'update-rules') {
    if (!defined($rule_dir)) {
        print "Error: must include ruledir\n";
        exit 1;
    }
    print "update rules\n" if $debug;
    $rc = update_rules($rule_dir, $disable_file, $enable_file);
}

exit $rc;

# end of file
