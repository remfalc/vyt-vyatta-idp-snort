# Author: An-Cheng Huang <ancheng@vyatta.com>
# Date: 2008
# Description: Perl module for processing Snort Unified log files.

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
# Portions created by Vyatta are Copyright (C) 2006, 2007, 2008 Vyatta, Inc.
# All Rights Reserved.
# **** End License ****

package VyattaSnortUnifiedLog;

use strict;
use NetAddr::IP;
use Fcntl qw(SEEK_SET SEEK_END);

BEGIN {
  use Exporter;
  our @ISA = qw(Exporter);
  our @EXPORT = qw(&open_log_file
                   &seek_to_log_entry
                   &get_next_log_entry
                   &print_log_entry
                   &get_class_strs
                   &get_sig_msg);
  our @EXPORT_OK = qw(%proto_hash %class_hash %sidmsg_hash);
}

my $UNIFIED_MAGIC = 0xDEAD4137;
my $PROTO_FILE = '/etc/protocols';
my $SNORT_PATH = '/etc/snort';
my $CLASS_FILE = "$SNORT_PATH/classification.config";
my $SIDMSG_FILE = "$SNORT_PATH/sid-msg.map";
my $COMMSG_FILE = "$SNORT_PATH/community-sid-msg.map";

my %proto_hash = ();
my %class_hash = ();
my %sidmsg_hash = ();

sub process_protocols {
  my $proto = undef;
  # do nothing if can't open
  return if (!open($proto, $PROTO_FILE));
  while (<$proto>) {
    next if (/^\s*#/);
    next if (!/^\S+\s+(\d+)\s+(\S+)\s/);
    $proto_hash{$1} = $2;
  }
  close $proto;
}

sub process_classes {
  my $class = undef;
  # do nothing if can't open
  return if (!open($class, $CLASS_FILE));
  my $idx = 1;
  while (<$class>) {
    next if (/^\s*#/);
    next if (!/^config classification: ([^,]+),([^,]+),\s*(\d+)/);
    $class_hash{$idx} = [ $1, $2, $3 ];
    $idx++;
  }
  close $class;
}

sub process_sidmsgs {
  for my $file ($SIDMSG_FILE, $COMMSG_FILE) {
    my $msg = undef;
    # do nothing if can't open
    next if (!open($msg, $file));
    while (<$msg>) {
      next if (!/^(\d+) \|\| ([^\|]+\S) *(\|\||$)/);
      $sidmsg_hash{$1} = $2;
      chomp $sidmsg_hash{$1};
    }
    close $msg;
  }
}

# opens and prepares a log file for subsequent reading.
# arg: log_file_name
# returns (undef, handle) if successful.
# otherwise returns (error_message, ).
sub open_log_file {
  my ($log) = @_;
  my $log_handle = undef;
  open($log_handle, "<$log") or return ("Cannot open $log: $!", );

  # prepare the cache
  process_protocols() if (scalar(keys %proto_hash) <= 0);
  process_classes() if (scalar(keys %class_hash) <= 0);
  process_sidmsgs() if (scalar(keys %sidmsg_hash) <= 0);

  # header:
  #   L: magic
  #   L: ver_major
  #   L: ver_minor
  #   L: timezone
  # total: 16 bytes
  my ($hdr, $count) = (undef, 0);
  return ("Read failed: $!", )
    if (!defined($count = sysread($log_handle, $hdr, 16)));
  return ('Read header failed', ) if ($count != 16);
  my ($magic, $vmaj, $vmin, $tz) = unpack('L[4]', $hdr);
  return ('Invalid log file', ) if ($magic != $UNIFIED_MAGIC);
  return (undef, $log_handle);
}

# get the next entry in the log file. file must have been opened by a
# call to open_log_file.
# arg: log_handle
# returns (error_message, ) if it fails.
# returns (undef, undef, ) if it reaches end-of-file.
# otherwise returns (undef, date, time, sgen, sid, srev, class, prio,
#                    sip, dip, sp, dp, proto)
sub get_next_log_entry {
  my ($log_handle) = @_;
  return ('Log file is not open', ) if (!defined($log_handle)); 

  # entry:
  #   event:
  #     L: sig_gen
  #     L: sig_id
  #     L: sig_rev
  #     L: class
  #     L: priority
  #     L: ev_id
  #     L: ev_ref
  #     ref_time
  #       L: sec
  #       L: usec
  #   time:
  #     L: sec
  #     L: usec
  #   L: sip
  #   L: dip
  #   S: sp
  #   S: dp
  #   L: proto
  #   L: flags
  # total: 64 bytes
  my ($entry, $count) = (undef, 0);
  return ("Read failed: $!", )
    if (!defined($count = sysread($log_handle, $entry, 64)));
  if ($count != 64) {
    close $log_handle;
    $log_handle = undef;
    return (undef, undef, );
  }

  my ($sgen, $sid, $srev, $class, $prio, $eid, $eref, $refs, $refus,
      $ts, $tus, $sip, $dip, $sp, $dp, $proto, $flags)
    = unpack('L[13]S[2]L[2]', $entry);
  my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) 
    = localtime($ts);
  $year += 1900;
  $mon += 1;
  my $date = sprintf("%04u-%02u-%02u", $year, $mon, $mday);
  my $time = sprintf("%02u:%02u:%02u.%06u", $hour, $min, $sec, $tus);
  my $sip = (NetAddr::IP->new($sip))->addr();
  my $dip = (NetAddr::IP->new($dip))->addr();

  return (undef, $date, $time, $sgen, $sid, $srev, $class, $prio,
          $sip, $dip, $sp, $dp, $proto);
}

# seek to the log entry with the specified index.
# args: log_handle index
#   negative index means the number of entries from the end.
# returns an error message if it fails. otherwise returns undef.
sub seek_to_log_entry {
  my ($log_handle, $idx) = @_;
  return 'Log file is not open' if (!defined($log_handle)); 

  # each entry is 64-byte (see get_next_log_entry())
  $idx *= 64;
  if ($idx < 0) {
    return "Seek failed: $!" if (!sysseek($log_handle, $idx, SEEK_END));
  } elsif ($idx > 0) {
    # file header is 16-byte (see open_log_file())
    return "Seek failed: $!" if (!sysseek($log_handle, ($idx + 16), SEEK_SET));
  }
  return undef;
}

# returns the short name and the description of the class.
# arg: class_id
sub get_class_strs {
  my $class = shift;
  return (defined($class_hash{$class}))
         ? (@{$class_hash{$class}}) : ('unknown', 'Unknown class');
}

# returns the description of a particular signature.
# arg: "gen:id:rev"
sub get_sig_msg {
  my ($sgen, $sid, $srev) = split /:/, $_[0];
  return (defined($sidmsg_hash{$sid}) && $sgen eq '1')
         ? $sidmsg_hash{$sid} : 'Unknown signature';
}

# format and print a log entry
# args: those returned by get_next_log_entry()
sub print_log_entry {
  my ($date, $time, $sgen, $sid, $srev, $class, $prio, $sip, $dip,
      $sp, $dp, $proto) = @_;
  my $proto_str = (defined($proto_hash{$proto}))
                  ? $proto_hash{$proto} : $proto;
  my $show_port = ($proto eq '6' || $proto eq '17') ? 1 : 0;

  my ($cname, $cdesc) = get_class_strs($class);
  my $class_str = "($cname) $cdesc";

  my $sid_str = "$sgen:$sid:$srev";
  my $msg_str = get_sig_msg($sid_str);

  my $addr_str = ($show_port) ? "$sip:$sp -> $dip:$dp" : "$sip -> $dip";

  print <<EOF;
$date $time {$proto_str} $addr_str
$class_str (priority $prio)
[$sid_str] $msg_str
---------------------------------------------------------------------------
EOF
}

1;

