#!/usr/bin/perl

use strict;
use Getopt::Long;

sub usage {
  print <<EOF;
Arguments:
  --classfile <file>    Location of the classification file
  --ruledir <dir>       Directory containing the rules
  --outdir <dir>        Directory for outputing the rules
EOF
}

my $class_file = undef;
my $rule_dir = undef;
my $out_dir = undef;
GetOptions('classfile=s' => \$class_file,
           'ruledir=s' => \$rule_dir,
           'outdir=s' => \$out_dir);
if (!defined($class_file) || !defined($rule_dir) || !defined($out_dir)) {
  usage();
  exit 1;
}

my %class_hash = ();
my %prio_hash = ( '1' => 'p1action',
                  '2' => 'p2action',
                  '3' => 'p3action',
                  'default' => 'p4action' );

open(CLASS, "<$class_file") or die "Cannot open $class_file: $!";
while (<CLASS>) {
  next if (!/^\s*config\s+classification:\s+(.*)$/);
  my ($name, $desc, $prio) = split /,/, $1;
  $prio =~ s/\s*(\d+)\s*/$1/;
  $class_hash{$name} = $prio;
}
close CLASS;

opendir(RIN_DIR, "$rule_dir") or die "Cannot open $rule_dir: $!";
my @rule_files = grep /\.rules$/, readdir(RIN_DIR);
closedir RIN_DIR;

if (! -d $out_dir) {
  mkdir($out_dir) or die "Cannot create $out_dir: $!";
}

foreach my $file (@rule_files) {
  open(RIN, "<$rule_dir/$file") or die "Cannot open $rule_dir/$file: $!";
  open(ROUT, ">$out_dir/$file") or die "Cannot open $out_dir/$file: $!";
  while (<RIN>) {
    if (!/^alert\s/) {
      print ROUT;
      next;
    }
    my $prio = undef;
    if (/[(; ]classtype:\s*([^;]+);/) {
      $prio = $class_hash{$1};
    }
    if (/[(; ]priority:\s*([^;]+);/) {
      $prio = $1;
    }
    if (!defined($prio)) {
      print ROUT;
      next;
    }
    if (!defined($prio_hash{$prio})) {
      print "prio [$prio] not defined\n";
    }
    my $action = (defined($prio_hash{$prio}))
                    ? $prio_hash{$prio} : $prio_hash{'default'};
    s/^alert\s/$action /;
    print ROUT;
  }
  close RIN;
  close ROUT;
}

