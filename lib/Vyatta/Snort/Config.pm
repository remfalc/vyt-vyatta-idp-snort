package Vyatta::Snort::Config;

use strict;
use lib '/opt/vyatta/share/perl5';
use Vyatta::Config;
use File::Copy;
use Sys::Hostname;
use File::Compare;

my $cfg_delim_begin = '# === BEGIN VYATTA SNORT CONFIG ===';
my $cfg_delim_end = '# === END VYATTA SNORT CONFIG ===';
my $post_fw_hook = 'VYATTA_POST_FW_HOOK';
# non-user chain must be 'VYATTA_*_HOOK'
my $queue_prefix = 'VYATTA_SNORT_';
my $queue_suffix = '_HOOK';

my $SNORT_INIT = '/etc/init.d/snort';
my $SNORT_DONE = '/var/run/snort_inline_init.pid';

my %fields = (
  _tr_preset => undef,
  _tr_custom => undef,
  _tr_ipv6_preset => undef,
  _tr_ipv6_custom => undef,
  _p1act     => undef,
  _p2act     => undef,
  _p3act     => undef,
  _p4act     => undef,
  _au_oink   => undef,
  _au_hour   => undef,
  _au_vrtsub => undef,
  _is_empty  => 1,
  _db_type   => undef,
  _db_dbname => undef,
  _db_host   => undef,
  _db_user   => undef,
  _db_passwd => undef,
  _sl_fac    => undef,
  _sl_level  => undef,
);

sub new {
  my $that = shift;
  my $class = ref ($that) || $that;
  my $self = {
    %fields,
  };

  bless $self, $class;
  return $self;
}

sub setup {
  my ( $self ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel('content-inspection traffic-filter');
  $self->{_tr_preset} = $config->returnValue('preset');
  $self->{_tr_custom} = $config->returnValue('custom');
  $self->{_tr_ipv6_preset} = $config->returnValue('ipv6-preset');
  $self->{_tr_ipv6_custom} = $config->returnValue('ipv6-custom');

  $config->setLevel('content-inspection ips');
  my @nodes = $config->listNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

  $self->{_p1act} = $config->returnValue('actions priority-1');
  $self->{_p2act} = $config->returnValue('actions priority-2');
  $self->{_p3act} = $config->returnValue('actions priority-3');
  $self->{_p4act} = $config->returnValue('actions other');
  
  $self->{_au_oink} = $config->returnValue('auto-update oink-code');
  $self->{_au_hour} = $config->returnValue('auto-update update-hour');
  $self->{_au_vrtsub} = $config->exists('auto-update snortvrt-subscription');
  
  $config->setLevel('content-inspection ips output remote-db');
  $self->{_db_type}   = $config->returnValue('db-type');
  $self->{_db_dbname} = $config->returnValue('db-name');
  $self->{_db_host}   = $config->returnValue('host');
  $self->{_db_user}   = $config->returnValue('username');
  $self->{_db_passwd} = $config->returnValue('password');

  $config->setLevel('content-inspection ips output syslog');
  $self->{_sl_fac}   = $config->returnValue('facility');
  $self->{_sl_level} = $config->returnValue('level');

  return 0;
}

sub setupOrig {
  my ( $self ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel('content-inspection traffic-filter');
  $self->{_tr_preset} = $config->returnOrigValue('preset');
  $self->{_tr_custom} = $config->returnOrigValue('custom');
  $self->{_tr_ipv6_preset} = $config->returnOrigValue('ipv6-preset');
  $self->{_tr_ipv6_custom} = $config->returnOrigValue('ipv6-custom');

  $config->setLevel('content-inspection ips');
  my @nodes = $config->listOrigNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

  $self->{_p1act} = $config->returnOrigValue('actions priority-1');
  $self->{_p2act} = $config->returnOrigValue('actions priority-2');
  $self->{_p3act} = $config->returnOrigValue('actions priority-3');
  $self->{_p4act} = $config->returnOrigValue('actions other');
  
  $self->{_au_oink} = $config->returnOrigValue('auto-update oink-code');
  $self->{_au_hour} = $config->returnOrigValue('auto-update update-hour');
  $self->{_au_vrtsub} = $config->existsOrig('auto-update snortvrt-subscription');
  
  $config->setLevel('content-inspection ips output remote-db');
  $self->{_db_type}   = $config->returnOrigValue('db-type');
  $self->{_db_dbname} = $config->returnOrigValue('db-name');
  $self->{_db_host}   = $config->returnOrigValue('host');
  $self->{_db_user}   = $config->returnOrigValue('username');
  $self->{_db_passwd} = $config->returnOrigValue('password');

  $config->setLevel('content-inspection ips output syslog');
  $self->{_sl_fac}   = $config->returnOrigValue('facility');
  $self->{_sl_level} = $config->returnOrigValue('level');

  return 0;
}

sub checkAutoUpdate {
  my ($self, $orig) = @_;
  my $config = new Vyatta::Config;
  my $exists = ($orig) ?
                  $config->existsOrig('content-inspection ips auto-update')
                  : $config->exists('content-inspection ips auto-update');
  if ($exists) {
    if (!defined($self->{_au_hour})) {
      return ('NONE NONE',
              '"update-hour" must be set');
    }
    if (defined($self->{_au_oink}) && defined($self->{_au_vrtsub})) {
      return ('NONE NONE', 
              'cant set both "oink-code" and "snortvrt-subscription"');
    }
    if (!defined($self->{_au_oink}) && !defined($self->{_au_vrtsub})) {
      return ('NONE NONE', 
              'must define "oink-code" unless using "snortvrt-subscription"');
    }
  } else {
    return ('NONE NONE', undef);
  }

  my $file   = "/etc/cron.hourly/vyatta-ips-update";  
  my $output = '';
  if (!$orig && $self->{_au_oink}) {
    my $update_hour = $self->{_au_hour};
    my $oink        = $self->{_au_oink};
    
    $update_hour =~ s/^0*//;
    $update_hour = 0 if ($update_hour eq '');

    my $rules   = "snortrules-snapshot-2861.tar.gz";
    my $get_cmd = "/opt/vyatta/sbin/vyatta-get-snort-rules.pl $rules";

    $output  = '#!/bin/bash' . "\n#\n";
    $output .= '# autogenerated by Vyatta::Snort::Config.pm' ."\n#\n";
    $output .= '# cron job to automatically update the snort rules' . "\n";
    $output .= '#' . "\n\n";
    $output .= '# when invoked from cron, we dont have these variables' . "\n";
    $output .= 'export VYATTA_EDIT_LEVEL=\'/\'' . "\n";
    $output .= 'export VYATTA_TEMPLATE_LEVEL=\'/\'' . "\n";
    $output .= 'export VYATTA_ACTIVE_CONFIGURATION_DIR=\'/opt/vyatta/config/active\'' . "\n\n";
    $output .= 'cur_hour=$(date +%-H)' . "\n";
    $output .= 'if [ "$cur_hour" != "' . $update_hour . '" ]; then' . "\n";
    $output .= '  # not the right hour. do nothing.' . "\n";
    $output .= '  exit 0' . "\n";
    $output .= 'fi' . "\n\n";
    $output .= 'if  ' . "$get_cmd " . ' ; then' . "\n";
    $output .= '   /opt/vyatta/sbin/vyatta-proc-snort-updates';
    $output .= " /tmp/$rules " . '>/dev/null 2>&1' . "\n";
    $output .= 'fi' . "\n\n";
  } elsif (!$orig && $self->{_au_vrtsub}) {
    my $update_hour = $self->{_au_hour};
  
    $update_hour =~ s/^0*//;
    $update_hour = 0 if ($update_hour eq '');

    my $base_dir = '/opt/vyatta/etc/ips';
    if (! -e $base_dir) {
        system("mkdir -p $base_dir");
    }

    my $rules   = "snortrules-snapshot-2861.tar.gz";
    my $get_cmd = "/opt/vyatta/sbin/vg_snort_update -q ";

    $output  = '#!/bin/bash' . "\n#\n";
    $output .= '# autogenerated by Vyatta::Snort::Config.pm' ."\n#\n";
    $output .= '# cron job to automatically update the ' . "\n";
    $output .= '# snort VRT subscription rules from vyatta portal' . "\n#\n";
    $output .= '# WARNING: You will NOT be able to download ' . "\n";
    $output .= '#          without a valid entitlement key.' . "\n";
    $output .= '#' . "\n\n";
    $output .= 'cur_hour=$(date +%-H)' . "\n";
    $output .= 'if [ "$cur_hour" != "' . $update_hour . '" ]; then' . "\n";
    $output .= '  # not the right hour. do nothing.' . "\n";
    $output .= '  exit 0' . "\n";
    $output .= 'fi' . "\n\n";
    $output .= 'if  ' . "$get_cmd " . ' ; then' . "\n";
    $output .= '   /opt/vyatta/sbin/vyatta-proc-snort-updates';
    $output .= " /tmp/$rules " . '>/dev/null 2>&1' . "\n";
    $output .= 'fi' . "\n\n";
  }

  if ($output ne '') {
    open(my $fh, '>', $file) || die "Couldn't open $file - $!";
    print $fh $output;
    close $fh;

    system("chmod 755 $file");
  }

  return ("$self->{_au_oink} $self->{_au_hour}", undef);
}

sub isDifferentFrom {
  my ($this, $that) = @_;

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_tr_preset} ne $that->{_tr_preset});
  return 1 if ($this->{_tr_custom} ne $that->{_tr_custom});
  return 1 if ($this->{_tr_ipv6_preset} ne $that->{_tr_ipv6_preset});
  return 1 if ($this->{_tr_ipv6_custom} ne $that->{_tr_ipv6_custom});
  return 1 if ($this->{_p1act} ne $that->{_p1act});
  return 1 if ($this->{_p2act} ne $that->{_p2act});
  return 1 if ($this->{_p3act} ne $that->{_p3act});
  return 1 if ($this->{_p4act} ne $that->{_p4act});

  return 1 if ($this->{_db_dbname} ne $that->{_db_dbname});
  return 1 if ($this->{_db_host}   ne $that->{_db_host});
  return 1 if ($this->{_db_user}   ne $that->{_db_user});
  return 1 if ($this->{_db_passwd} ne $that->{_db_passwd});

  return 1 if ($this->{_sl_fac}   ne $that->{_sl_fac});
  return 1 if ($this->{_sl_level} ne $that->{_sl_level});

  # ignore auto-update changes
  
  return 0;
}

sub isEmpty {
  my ($this) = @_;
  return $this->{_is_empty};
}

sub rule_num_sort {
  my ($a, $b) = (@_);
  my @aa = split /\s+/, $a;
  my @ab = split /\s+/, $b;
  return ($ab[0] <=> $aa[0]);
}

# Check whether a chain exists in the IPv4 filter table
sub chainExists {
  my $chain = shift;
  system("iptables -L $chain -vn >&/dev/null");
  return 0 if ($? >> 8);
  return 1;
}

# Check whether a chain exists in the IPv6 filter table
sub chainExistsIPv6 {
  my $chain = shift;
  system("ip6tables -L $chain -vn >&/dev/null");
  return 0 if ($? >> 8);
  return 1;
}

# Set up the chains for the "all" preset in both the IPv4 and IPv6 fiter
# tables.
sub setupIptables {
  my ($self) = @_;
  my %create_hash = ();
  my %create_hash_ipv6 = ();
  my @cmds = ();
  my @presets = qw( all );
  foreach (@presets) {
    my $chain = $queue_prefix . $_ . $queue_suffix;
    if (!chainExists($chain)) {
      $create_hash{$_} = 1;
    }
    if (!chainExistsIPv6($chain)) {
      $create_hash_ipv6{$_} = 1;
    }
  }

  # set up preset "all" for IPv4 and IPv6
  my $chain = $queue_prefix . 'all' . $queue_suffix;
  if ($create_hash{'all'}) {
    push @cmds,
      "iptables -N $chain",
      "iptables -A $chain -j QUEUE";
  }
  if ($create_hash_ipv6{'all'}) {
    push @cmds,
      "ip6tables -N $chain",
      "ip6tables -A $chain -j QUEUE";
  }

  # run all commands
  foreach (@cmds) {
    system("$_ >&/dev/null");
    return "Cannot setup iptables/ip6tables: ($_)" if ($? >> 8);
  }

  # return success
  return undef;
}

# Remove a rule jumping to a preset or custom chain located in the
# Vyatta post firewall hook chain of either the IPv4 or IPv6
# filter table.
sub removeChain {
    my ($cmd, $chain) = @_;

    my $grep = "grep ^[0-9] | grep $chain";
    my @lines = `$cmd -L $post_fw_hook -n --line-number | $grep`;
    @lines = sort rule_num_sort @lines;
    # rule number from high to low
    foreach (@lines) {
	my ($num, $target) = split /\s+/;
	next if ($target ne $chain);
	system("$cmd -D $post_fw_hook $num");
	return 'Cannot remove rule from iptables/ip6tables' if ($? >> 8);
    }

    return undef;
}

# Remove all of the rules we've added located in the Vyatta post firewall
# hook chain of either the IPv4 or IPv6 filter table.
sub removeQueue {
  my ($self) = @_;
  my $chain = undef;
  my $ret1 = undef;
  my $ret2 = undef;

  if (defined($self->{_tr_preset})) {
    $chain = $queue_prefix . $self->{_tr_preset} . $queue_suffix;
  } elsif (defined($self->{_tr_custom})) {
    $chain = $self->{_tr_custom};
  }

  if (defined($chain)) {
      $ret1 = removeChain ("iptables", $chain);
  }

  $chain = undef;
  if (defined($self->{_tr_ipv6_preset})) {
    $chain = $queue_prefix . $self->{_tr_ipv6_preset} . $queue_suffix;
  } elsif (defined($self->{_tr_ipv6_custom})) {
    $chain = $self->{_tr_ipv6_custom};
  }

  if (defined($chain)) {
      $ret2 = removeChain ("ip6tables", $chain);
  }

  if (defined($ret1)) {
      return $ret1;
  } elsif (defined($ret2)) {
      return $ret2;
  }

  # return success
  return undef;
}

# Validate configuration under "traffic-filter".
sub checkQueue {
  my ($self) = @_;
  return 'Must define "traffic-filter"'
    if (!defined($self->{_tr_preset}) && !defined($self->{_tr_custom}) &&
	!defined($self->{_tr_ipv6_preset}) && 
	!defined($self->{_tr_ipv6_custom}));

  return 'Cannot define both "preset" and "custom" for "traffic-filter"'
    if (defined($self->{_tr_preset}) && defined($self->{_tr_custom}));

  return 'Cannot define both "ipv6-preset" and "ipv6-custom" for "traffic-filter"'
    if (defined($self->{_tr_ipv6_preset}) && 
	defined($self->{_tr_ipv6_custom}));

  if (defined($self->{_tr_custom})) {
    my $chain = $self->{_tr_custom};
    system("iptables -L $chain -n >&/dev/null");
    if ($? >> 8) {
      return "Custom chain \"$chain\" is not valid in IPv4 filter table";
    }
  }

  if (defined($self->{_tr_ipv6_custom})) {
    my $chain = $self->{_tr_ipv6_custom};
    system("ip6tables -L $chain -n >&/dev/null");
    if ($? >> 8) {
      return "Custom chain \"$chain\" is not valid in IPv6 filter table";
    }
  }

  return undef;
}

# Based on the configuration parameters under "traffic-filter", add
# rules to the Vyatta post firewall hook of the IPv4 or IPv6 filter tables
# jumping to our preset or user defined chains.
sub addQueue {
  my ($self) = @_;
  my $chain = undef;

  if (defined($self->{_tr_preset})) {
    $chain = $queue_prefix . $self->{_tr_preset} . $queue_suffix;
  } elsif (defined($self->{_tr_custom})) {
    $chain = $self->{_tr_custom};
  }

  if (defined($chain)) {
      # insert rule at the front (ACCEPT at the end)
      system("iptables -I $post_fw_hook 1 -j $chain");
      return 'Cannot insert rule into iptables' if ($? >> 8);
  }

  $chain = undef;
  if (defined($self->{_tr_ipv6_preset})) {
    $chain = $queue_prefix . $self->{_tr_ipv6_preset} . $queue_suffix;
  } elsif (defined($self->{_tr_ipv6_custom})) {
    $chain = $self->{_tr_ipv6_custom};
  }

  if (defined($chain)) {
      system("ip6tables -I $post_fw_hook 1 -j $chain");
      return 'Cannot insert rule into ip6tables' if ($? >> 8);
  }

  # return success
  return undef;
}


# remove iptables queue rule(s) and stop snort (must be in this order).
# note: this should be invoked on "original" config.
# returns error message, or undef if success.
sub shutdownSnort {
  my ($self) = @_;
  my $err = $self->removeQueue();
  if (!defined($err)) {
    system("$SNORT_INIT stop >&/dev/null");
    if ($? >> 8) {
      $err = 'Stopping failed';
    }
  }
  return $err;
}

# start snort and add iptables queue rule(s) (must be in this order).
# note: this should be invoked on "new" config.
# returns error message, or undef if success.
sub startSnort {
  my ($self) = @_;

  my $err = $self->checkQueue();
  return $err if (defined($err));

  system("$SNORT_INIT start >&/dev/null");
  return 'Starting failed' if ($? >> 8);
  
  # wait for snort to finish initialization before adding queue rules
  # to avoid blocking traffic
  my $count = 0;
  $| = 1;
  while ($count < 120 && (! -f $SNORT_DONE)) {
    print '.';
    sleep 2;
    $count++;
  }
  return 'Initialization failed' if ($count == 120);

  # add iptables queue rule(s)
  return $self->addQueue();
}

sub isEmpty {
  my ($self) = @_;
  return $self->{_is_empty};
}

sub get_snort_conf {
  my ($self) = @_;

  return (undef, 'Action for "priority-1" not defined')
    if (!defined($self->{_p1act}));
  return (undef, 'Action for "priority-2" not defined')
    if (!defined($self->{_p2act}));
  return (undef, 'Action for "priority-3" not defined')
    if (!defined($self->{_p3act}));
  return (undef, 'Action for "other" not defined')
    if (!defined($self->{_p4act}));

  my $remote_logging;
  my ($output_def, $out_type, $out_file);
  if ($self->{_db_dbname} or $self->{_sl_fac}) {
      # barnyard2 expect unified2 format
      $out_type = 'unified2';
      $out_file = 'snort-unified2.log';
      $remote_logging = 1;
  } else {
      # just log alerts when storing locally
      $out_type = 'alert_unified';
      $out_file = 'snort-unified.alert';
      $remote_logging = 0;
  }
  $output_def = "output $out_type: filename $out_file, limit 1";

  # drop rule
  my $rule_drop_def   = "{\n"
                      . "   type drop\n" 
                      . "   $output_def\n";
     $rule_drop_def  .= "   output log_null\n" if ! $remote_logging;
     $rule_drop_def  .= "}\n";

  # sdrop rule
  my $rule_sdrop_def  = "{\n"
                      . "   type sdrop\n" 
                      . "   output log_null\n"
                      . "}\n";

  # alert rule
  my $rule_alert_def  = "{\n"
                      . "   type alert\n" 
                      . "   $output_def\n";
     $rule_alert_def .= "   output log_null\n" if ! $remote_logging;
     $rule_alert_def .= "}\n";

  # pass rule
  my $rule_pass_def  = "{\n"
                     . "  type pass\n"
                     . "  output log_null\n"
                     . "}\n";

  my %ruletype_defs  = ( 'drop'  => $rule_drop_def,
                         'sdrop' => $rule_sdrop_def,
                         'alert' => $rule_alert_def,
                         'pass'  => $rule_pass_def );


  # add actions
  my $cfg = "\n## actions\n";
  my @actions = ($self->{_p1act}, $self->{_p2act}, $self->{_p3act},
                 $self->{_p4act});
  for my $i (1 .. 4) {
    my $action = $actions[$i - 1];
    my $def = $ruletype_defs{$action};
    return (undef, "Action type \"$action\" not defined") if (!defined($def));
    $cfg .= "ruletype p${i}action\n$def\n";
  }
  $cfg .= <<EOS;
## include clamav config
include clamav.config

## set output module
output alert_null
output log_null

EOS

  return ($cfg, undef);
}

sub removeCfg {
  my ($self, $file) = @_;
  # write empty between markers
  return writeCfg($self, $file, '');
}

sub writeCfg {
  my ($self, $file, $cfg) = @_;
  my $tmpf = $file;
  $tmpf =~ s/\//_/g;
  $tmpf = "/tmp/vyatta_$tmpf.$$";
  return "Cannot create temporary file $tmpf: $!" if (!copy($file, $tmpf));
  open(FIN, "<$file") or return "Cannot open $file: $!";
  open(FOUT, ">$tmpf") or return "Cannot open $tmpf: $!";
  my ($skip, $vbegin, $vend) = (0, 0, 0);
  while (<FIN>) {
    if (/^$cfg_delim_begin$/) {
      $skip = 1;
      $vbegin = 1;
      print FOUT;
      print FOUT $cfg;
      next;
    } elsif (/^$cfg_delim_end$/) {
      $skip = 0;
      $vend = 1;
    } elsif ($skip) {
      next;
    }
    print FOUT;
  }
  close FIN;
  close FOUT;
  return "Invalid config file: missing Vyatta marker(s)"
    if (!$vbegin || !$vend);
  return "Cannot create config file $file: $!" if (!move($tmpf, $file));
  # return success
  return undef;
}

sub print_str {
  my ($self) = @_;
  my $str = 'ips';
  $str .= "\n  preset " . $self->{_tr_preset};
  $str .= "\n  custom " . $self->{_tr_custom};
  $str .= "\n  p1act " . $self->{_p1act};
  $str .= "\n  p2act " . $self->{_p2act};
  $str .= "\n  p3act " . $self->{_p3act};
  $str .= "\n  p4act " . $self->{_p4act};
  $str .= "\n  empty " . $self->{_is_empty};
  $str .= "\n";

  return $str;
}


#
# barnyard2 crap below, maybe should move to Barnyard.pm
#

my $by_daemon = '/usr/bin/barnyard2';
my $by_logdir = '/var/log/barnyard2';
my $by_pid    = '/var/run/barnyard2_NULL.pid';
my $by_conf   = '/etc/snort/barnyard2.conf';

my %fac_hash = (
    'auth'     => 'LOG_AUTH',
    'authpriv' => 'LOG_AUTHPRIV',
    'cron'     => 'LOG_CRON',
    'daemon'   => 'LOG_DAEMON',
    'kern'     => 'LOG_KERN',
    'lpr'      => 'LOG_LPR',
    'mail'     => 'LOG_MAIL',
    'news'     => 'LOG_NEWS',
    'syslog'   => 'LOG_SYSLOG',
    'user'     => 'LOG_USER',
    'uucp'     => 'LOG_UUCP',
    'local0'   => 'LOG_LOCAL0',
    'local1'   => 'LOG_LOCAL1',
    'local2'   => 'LOG_LOCAL2',
    'local3'   => 'LOG_LOCAL3',
    'local4'   => 'LOG_LOCAL4',
    'local5'   => 'LOG_LOCAL5',
    'local6'   => 'LOG_LOCAL6',
);

my %level_hash = (
    'emerg'   => 'LOG_EMERG',
    'alert'   => 'LOG_ALERT',
    'crit'    => 'LOG_CRIT',
    'err'     => 'LOG_ERR',
    'warning' => 'LOG_WARNING',
    'notice'  => 'LOG_NOTICE',
    'info'    => 'LOG_INFO',
    'debug'   => 'LOG_DEBUG'
);

sub get_by_conf {
  my ($self) = @_;
    
  my $output = '';
  my $host = hostname();
  
  $output  = "#\n# autogenerated barnyard2.conf\n#\n \n";

  $output .= "config hostname: $host\n" if defined $host; 
  $output .= "config alert_with_interface_name\n";
  $output .= "config quiet\n";
  $output .= "config logdir: $by_logdir\n";
  $output .= "config archivedir: /dev/null\n";
  $output .= "config reference_file: /etc/snort/reference.config\n";
  $output .= "config gen_file: /etc/snort/gen-msg.map\n";
  $output .= "config sid_file: /etc/snort/sid-msg.map\n";
  $output .= "config waldo_file: $by_logdir/waldo\n";
  $output .= "config process_new_records_only\n";
  $output .= "\ninput unified2\n\n";

  return $output;
}

sub get_db_conf {
  my ($self) = @_;
    
  my $output = '';

  return $output if ! defined $self->{_db_type};
  return $output if ! defined $self->{_db_host};
  return $output if ! defined $self->{_db_dbname};
  return $output if ! defined $self->{_db_user};
  return $output if ! defined $self->{_db_passwd};

  $output .= "output database: log, $self->{_db_type}, "
           . "user=$self->{_db_user} "
           . "password=$self->{_db_passwd} "
           . "dbname=$self->{_db_dbname} "
           . "host=$self->{_db_host}\n";

  return $output;
}

sub get_sl_conf {
  my ($self) = @_;
    
  my $output = '';

  return $output if ! defined $self->{_sl_fac};
  return $output if ! defined $self->{_sl_level};

  # output alert_syslog: severity facility 

  my ($fac, $level);
  $fac   = $fac_hash{$self->{_sl_fac}};
  $level = $level_hash{$self->{_sl_level}};

  return $output if ! defined $fac or ! defined $level;

  $output .= "output alert_syslog: $level $fac\n";

  return $output;
}

sub is_same_as_file {
    my ($file, $value) = @_;

    return if ! -e $file;

    my $mem_file = '';
    open my $MF, '+<', \$mem_file or die "couldn't open memfile $!\n";
    print $MF $value;
    seek($MF, 0, 0);
    
    my $rc = compare($file, $MF);
    return 1 if $rc == 0;
    return;
}

sub conf_write_file {
    my ($file, $config) = @_;

    # Avoid unnecessary writes.  At boot the file will be the
    # regenerated with the same content.
    return if is_same_as_file($file, $config);

    open(my $fh, '>', $file) || die "Couldn't open $file - $!";
    print $fh $config;
    close $fh;
    return 1;
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

sub handle_barn {
  my ($self, $orig) = @_;

  my $output = '';
  my $pid;

  $output .= get_db_conf($self);
  $output .= get_sl_conf($self);

  if ($output ne '') {
      if (! -f $by_daemon) {
          print "Error: missing barnyard2 package.\n";
          return 1;
      }
  
      my $by_output = get_by_conf($self);
      
      $output = $by_output . $output;

      $pid = is_running($by_pid);
      if (!conf_write_file($by_conf, $output) and $pid > 0) {
          return 0;
      }
      if ($pid > 0) {
          system("kill -INT $pid");
      }
      my ($cmd, $rc);
      system("sudo rm -f /var/log/snort/snort-unified*");
      $cmd = "$by_daemon -c $by_conf -d /var/log/snort -f snort-unified2.log";
      # test the conf 1st
      $rc = system("sudo $cmd -T -q");
      if ($rc) {
          print "Error: testing $by_conf\n";
          system("sudo mv $by_conf /tmp");
          return 1;
      }
      print "Starting barnyard2 daemon\n";
      system("sudo $cmd -q -D --pid-path $by_pid");
  } else {
      $pid = is_running($by_pid);
      if ($pid > 0) {
          print "Stopping barnyard2\n";
          system("kill -INT $pid");
      } 
      system("sudo rm -f $by_conf");
      system("sudo rm -f /var/log/snort/snort-unified*");
      system("sudo rm -f $by_logdir/waldo");
  }
}

1;

