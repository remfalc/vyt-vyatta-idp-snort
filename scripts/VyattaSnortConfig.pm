package VyattaSnortConfig;

use strict;
use lib '/opt/vyatta/share/perl5';
use VyattaConfig;
use File::Copy;

my $cfg_delim_begin = '# === BEGIN VYATTA SNORT CONFIG ===';
my $cfg_delim_end = '# === END VYATTA SNORT CONFIG ===';
my $post_fw_hook = 'VYATTA_POST_FW_HOOK';
# non-user chain must be 'VYATTA_*_HOOK'
my $queue_prefix = 'VYATTA_SNORT_';
my $queue_suffix = '_HOOK';

my %fields = (
  _tr_preset => undef,
  _tr_custom => undef,
  _p1act     => undef,
  _p2act     => undef,
  _p3act     => undef,
  _p4act     => undef,
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
  my $config = new VyattaConfig;

  $config->setLevel('idp snort');
  my @nodes = $config->listNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

  $self->{_tr_preset} = $config->returnValue('traffic-selection preset');
  $self->{_tr_custom} = $config->returnValue('traffic-selection custom');
  $self->{_p1act} = $config->returnValue('actions priority-1');
  $self->{_p2act} = $config->returnValue('actions priority-2');
  $self->{_p3act} = $config->returnValue('actions priority-3');
  $self->{_p4act} = $config->returnValue('actions other');

  return 0;
}

sub setupOrig {
  my ( $self ) = @_;
  my $config = new VyattaConfig;

  $config->setLevel('idp snort');
  my @nodes = $config->listOrigNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

  $self->{_tr_preset} = $config->returnOrigValue('traffic-selection preset');
  $self->{_tr_custom} = $config->returnOrigValue('traffic-selection custom');
  $self->{_p1act} = $config->returnOrigValue('actions priority-1');
  $self->{_p2act} = $config->returnOrigValue('actions priority-2');
  $self->{_p3act} = $config->returnOrigValue('actions priority-3');
  $self->{_p4act} = $config->returnOrigValue('actions other');

  return 0;
}

sub isDifferentFrom {
  my ($this, $that) = @_;

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_tr_preset} ne $that->{_tr_preset});
  return 1 if ($this->{_tr_custom} ne $that->{_tr_custom});
  return 1 if ($this->{_p1act} ne $that->{_p1act});
  return 1 if ($this->{_p2act} ne $that->{_p2act});
  return 1 if ($this->{_p3act} ne $that->{_p3act});
  return 1 if ($this->{_p4act} ne $that->{_p4act});
  
  return 0;
}

sub rule_num_sort {
  my ($a, $b) = (@_);
  my @aa = split /\s+/, $a;
  my @ab = split /\s+/, $b;
  return ($ab[0] <=> $aa[0]);
}

sub chainExists {
  my $chain = shift;
  system("iptables -L $chain -vn >&/dev/null");
  return 0 if ($? >> 8);
  return 1;
}

sub setupIptables {
  my ($self) = @_;
  my %create_hash = ();
  my @cmds = ();
  my @presets = qw( all );
  foreach (@presets) {
    my $chain = $queue_prefix . $_ . $queue_suffix;
    if (!chainExists($chain)) {
      $create_hash{$_} = 1;
    }
  }

  # set up preset "all"
  my $chain = $queue_prefix . 'all' . $queue_suffix;
  if ($create_hash{'all'}) {
    push @cmds,
      "iptables -N $chain",
      "iptables -A $chain -j QUEUE";
  }

  # run all commands
  foreach (@cmds) {
    system("$_ >&/dev/null");
    return "Cannot setup iptables for Snort ($_)" if ($? >> 8);
  }

  # return success
  return undef;
}

sub removeQueue {
  my ($self) = @_;
  my $chain = undef;
  if (defined($self->{_tr_preset})) {
    $chain = $queue_prefix . $self->{_tr_preset} . $queue_suffix;
  } elsif (defined($self->{_tr_custom})) {
    $chain = $self->{_tr_custom};
  } else {
    # neither defined. nothing to remove. return success.
    return undef;
  }
  my $grep = "grep ^[0-9] | grep $chain";
  my @lines = `iptables -L $post_fw_hook -n --line-number | $grep`;
  @lines = sort rule_num_sort @lines;
  # rule number from high to low
  foreach (@lines) {
    my ($num, $target) = split /\s+/;
    next if ($target ne $chain);
    system("iptables -D $post_fw_hook $num");
    return 'Cannot remove rule from iptables' if ($? >> 8);
  }
  # return success
  return undef;
}

sub checkQueue {
  my ($self) = @_;
  return 'Traffic selection not defined'
    if (!defined($self->{_tr_preset}) && !defined($self->{_tr_custom}));
  return 'Cannot define both "preset" and "custom"'
    if (defined($self->{_tr_preset}) && defined($self->{_tr_custom}));
  return undef;
}

sub addQueue {
  my ($self) = @_;
  my $chain = undef;
  if (defined($self->{_tr_preset})) {
    $chain = $queue_prefix . $self->{_tr_preset} . $queue_suffix;
  } elsif (defined($self->{_tr_custom})) {
    $chain = $self->{_tr_custom};
  } else {
    # neither defined. return error.
    return 'Traffic selection not defined';
  }
  # insert rule at the front (ACCEPT at the end)
  system("iptables -I $post_fw_hook 1 -j $chain");
  return 'Cannot insert rule into iptables' if ($? >> 8);
  # return success
  return undef;
}

sub isEmpty {
  my ($self) = @_;
  return $self->{_is_empty};
}

my $log_limit = 1;
my $output_def =<<EOD;
  output alert_unified: alert, limit $log_limit
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
}
EOD

my %ruletype_defs = ( 'drop' => $rule_drop_def,
                      'sdrop' => $rule_sdrop_def,
                      'alert' => $rule_alert_def,
                      'pass' => $rule_pass_def );

sub get_snort_conf {
  my ($self) = @_;

  # add actions
  my $cfg = "\n## actions\n";
  # set default action if not set
  my @actions = ( ((defined($self->{_p1act})) ? $self->{_p1act} : 'drop'),
                  ((defined($self->{_p2act})) ? $self->{_p2act} : 'alert'),
                  ((defined($self->{_p3act})) ? $self->{_p3act} : 'alert'),
                  ((defined($self->{_p4act})) ? $self->{_p4act} : 'pass') );
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
output alert_fast: alert

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
  my $str = 'idp snort';
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

