package Vyatta::Snort::Config;

use strict;
use lib '/opt/vyatta/share/perl5';
use Vyatta::Config;
use File::Copy;

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
  _is_empty  => 1,
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
  
  return 0;
}

sub checkAutoUpdate {
  my ($self, $orig) = @_;
  my $config = new Vyatta::Config;
  my $exists = ($orig) ?
                  $config->existsOrig('content-inspection ips auto-update')
                  : $config->exists('content-inspection ips auto-update');
  if ($exists) {
    if (!defined($self->{_au_oink}) || !defined($self->{_au_hour})) {
      return ('NONE NONE',
              'Both "oink-code" and "update-hour" must be set');
    }
  } else {
    return ('NONE NONE', undef);
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

my $log_limit = 1;
my $output_def =<<EOD;
  output alert_unified: filename snort-unified.alert, limit $log_limit
  output log_null
EOD
my $rule_drop_def =<<EOD;
{
  type drop
$output_def
}
EOD
my $rule_sdrop_def =<<EOD;
{
  type sdrop
}
EOD
my $rule_alert_def =<<EOD;
{
  type alert
$output_def
}
EOD
my $rule_pass_def =<<EOD;
{
  type pass
$output_def
}
EOD

my %ruletype_defs = ( 'drop' => $rule_drop_def,
                      'sdrop' => $rule_sdrop_def,
                      'alert' => $rule_alert_def,
                      'pass' => $rule_pass_def );

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

  # add actions
  my $cfg = "\n## actions\n";
  my @actions = ($self->{_p1act}, $self->{_p2act}, $self->{_p3act},
                 $self->{_p4act});
  for my $i (1 .. 4) {
    my $action = $actions[$i - 1];
    my $def = $ruletype_defs{$action};
    return (undef, "Action type \"$action\" not defined") if (!defined($def));
    $cfg .= <<EOS;
ruletype p${i}action
$def
EOS
  }
  $cfg .= <<EOS;
## include clamav config
include clamav.config

## set output module
output alert_unified: filename snort-unified.alert, limit 1

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

1;

