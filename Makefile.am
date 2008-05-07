cfgdir		 = $(datadir)/vyatta-cfg/templates
opdir		 = $(datadir)/vyatta-op/templates
share_perl5dir	 = $(datarootdir)/perl5
bin_sudo_usersdir = $(bindir)/sudo-users
cron_hourlydir = /etc/cron.hourly

sbin_SCRIPTS = scripts/vyatta-update-snort.pl
sbin_SCRIPTS += scripts/vyatta-proc-snort-rules.pl
sbin_SCRIPTS += scripts/vyatta-update-inspection.pl
sbin_SCRIPTS += scripts/vyatta-show-ips.pl
sbin_SCRIPTS += scripts/vyatta-proc-snort-updates

cron_hourly_SCRIPTS = scripts/vyatta-ips-update

bin_sudo_users_SCRIPTS =

share_perl5_DATA = scripts/VyattaSnortConfig.pm
share_perl5_DATA += scripts/VyattaSnortUnifiedLog.pm

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)

