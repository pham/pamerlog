#!/usr/local/bin/perl -w
use strict;

=head1 PROGRAM

C<pamerlog.pl> - Parse MySQL error log for info and stats.

=head2 Usage

 ./pamerlog.pl -file <error-log> [-logs] [-days] -no[warning|error|note]
               -[unaccounted|hosts|schemas|logins] [-verbose]

Show last 5 days of the log in a consolidated format and suppress both
warnings and notes:

 ./pamerlog.pl -logs -days 5 -file mydatabase.err -nowarning -nonote

List all the hosts/IPs:

 ./pamerlog.pl -file mydatabase.err -hosts

=cut

use vars qw/$LOG/;

use constant HELP => qq{pamerlog.pl v1.0.1 
Formats MySQL error log for readability.
 ./pamerlog.pl -file <mysql-err-log>
   -logs          formatted log
   -days          number of days to look back

   -nonote        suppress notes
   -nowarning     suppress warnings
   -noerror       suppress errors

   -unaccounted   misc logs
   -hosts         connections to this DB
   -schemas       most troublesome tables
   -logins        users with problems

Show formatted logs for last five days and suppress notes:
 ./pamerlog -file mysql.err -logs -days 5 -nonote

Show IP/hosts that connected sort them by hits:
 ./pamerlog -file mysql.err -hosts
};

$LOG = ParseMyLog->new(@ARGV);
if ($LOG->{-file}) {
	$LOG->commands;
} else {
	print HELP;
}

exit (0);

=head1 NAME

C<ParseMyLog.pm> - Parse MySQL error log and provide statistics.

=head1 SYNOPSIS

 my $errlog = ParseMyLog->new(@ARGV);
 $errlog->commands;

=head1 DESCRIPTION

=cut

package ParseMyLog;
use Time::Local;

=head2 Public Methods

=head3 new

Accepts these command-line args:

 -file    = log file
 -verbose = dumps messages

=cut

sub new {
	my $class = shift;
	my $self = {};

	for (my $i=0;$i<=$#_;$i++) {
		if (substr($_[$i],0,1) eq '-') {
			$self->{$_[$i]} = 1;
		} else {
			$self->{$_[$i-1]} = $_[$i];
		}
	}

	bless $self, $class;

	return $self;
}

=head3 commands (I<void>)

Acts on commands passed:

 -logs           = prints out formatted logs
 -unacccounted   = prints the unaccounted messages
 -hosts          = prints IPs

=cut

sub commands {
	my $self = shift;

	$self->parse;

	if ($self->{-logs})
		{
		$self->logs;
		}

	if ($self->{-unaccounted})
		{
		$self->dump_stats('-uncount');
		}

	elsif ($self->{-hosts})
		{
		$self->dump_stats('-ips');
		}

	elsif ($self->{-schemas})
		{
		$self->dump_stats('-tables');
		}

	elsif ($self->{-logins})
		{
		$self->dump_stats('-users');
		}
}

=head3 dump_stats (I<void>)

Dumps out hashes with specific keys we captured.

=cut

sub dump_stats {
	my ($self,$stats) = (@_);

	return 0 unless $self->{$stats};

	foreach (sort 
		{ $self->{$stats}{$a} <=> $self->{$stats}{$b} } 
		keys %{ $self->{$stats} }) {
			printf "%5d %s\n",
				$self->{$stats}->{$_},
				$_;
	}

	return 1;
}

=head3 logs (I<void>)

Dumps out a formatted version of the logs. 
You can turn off certain error levels:

 -noerror   = suppress error messages
 -nowarning = suppress warning messages
 -nonote    = suppress notes

=cut

sub logs {
	my $self = shift;
	return 0 unless $self->{-log};

	foreach my $ts (sort keys %{ $self->{-log} }) {
		foreach my $lev (keys %{ $self->{-log}->{$ts} }) {
			next if $self->{'-no'.lc $lev};
			foreach my $msg (keys %{ $self->{-log}->{$ts}->{$lev} }) {
				printf "%s %-7s %3d %s\n",
					scalar localtime($ts),
					$lev,
					$self->{-log}->{$ts}->{$lev}->{$msg},
					$msg;
			}
		}	
	}

	return 1;
}

=head3 parse (I<void>)

Reads C<-file> and figure out what's inside of it.
Create these hashes:

 -log    = main hash
 -levels = records the number of log levels hit
 -days   = optional number of days to look back

=cut

sub parse {
	my $self = shift;

	$self->{-file} and -s $self->{-file}
		or die "ERROR: Tell me where the log -file is at\n";

	open LOG, $self->{-file} 
		or die "ERROR: Can't open $self->{-file}: $!\n";

	while (<LOG>) {
		chomp;
		my ($d,$t,$lev,$msg) = split /\s+/, $_, 4;	
		next if !$lev or $lev !~ s/\[([^\]]+)\]/$1/;

		my $ts = $self->_to_unixtime("$d$t");

		next if $self->{-days} && $ts <= $^T-($self->{-days}*86400);

		$self->{-levels}{$lev}++;

		$msg = $self->_format($msg);

		$msg and $self->{-log}{$ts}{$lev}{$msg}++;
	}
	close LOG;

	my $records = scalar keys %{$self->{-log}};

	$self->_printf("INFO: found %d records\n", $records);

	return $records;
}

=head2 Private Methods

=head3 _format (I<message>)

Figure out if this message is of any importance.
Creates several hashes:

 -ips     = IP addresses and number of hits
 -tables  = Tables that have issues
 -users   = Users issues
 -misc    = Misc. messages
 -uncount = Unaccounted messages

=cut

sub _format {
	my ($self,$msg) = (@_);

	if (($msg =~ /IP address '([^']+)'/) || 
		($msg =~ /- (\d+\.\d+\.\d+\.\d+)/i))
		{
		$msg = $1;
		$self->{-ips}{$1}++;
		} 

	elsif ($msg =~ /Hostname '([^']+)'([^']+'([^']+)')?/i) 
		{
		$msg = $3 ? "$3 [$1]" : $1;
		$self->{-ips}{$3||$1}++;
		} 

	elsif ($msg =~ /Table '\.?([^'\.]+)(.MYI)?'\;? (.*)/i) 
		{
		$self->{-tables}{$1}++;
		$msg = sprintf "$1 [%s]", 
			$3 =~ /crashed/ ? 'crashed' : 'repair needed';
		} 

	elsif ($msg =~ /definition of table ([^:]+)/i) 
		{
		$msg = "$1 [incorrect definition]";
		$self->{-tables}{$1}++;
		} 

	elsif ($msg =~ /(Native table|plugin)\s+'([^']+)'/i) 
		{
		$msg = sprintf "$2 [%s]", 
			$1 eq 'plugin' ? 'shutdown plugin' : 'wrong structure';
		$self->{-tables}{$2}++;
		} 

	elsif ($msg =~ /column count of ([^\s]+)/i) 
		{
		$msg = "$1 [wrong # columns]";
		$self->{-tables}{$1}++;
		} 

	elsif ($msg =~ /thread ([^ ]+)\s+user: '([^']+)'/i) 
		{
		$msg = "$2 [force close]";
		$self->{-users}{$2}++;
		} 

	elsif ($msg =~ /find file: '\.?([^']+)'/i) 
		{
		$msg = "$1 [missing]";
		$self->{-misc}{$msg}++;
		} 

	elsif ($msg =~ /thread[_ ]id[ =]([^,]+)/i) 
		{
		$msg = "$1 [thread]";
		$self->{-misc}{$msg}++;
		} 

	elsif ($msg =~ /ready for connections/i) 
		{
		$msg = "started";
		$self->{-misc}{$msg}++;
		} 

	elsif ($msg =~ /Shutdown complete/i) 
		{
		$msg = "stopped";
		$self->{-misc}{$msg}++;
		} 

	else 
		{
		$self->{-uncount}{$msg}++;
		return '';
		}

	return $msg;
}

=head3 _to_unixtime (I<YYMMDD HH:MM:SS>)

Translate MySQL's error log time signature to Unix timestamp.

=cut

sub _to_unixtime {
	my ($self,$str) = (@_);
	if ($str =~ /^(\d{2})(\d{2})(\d{2})\s*(\d{1,2}):(\d{2}):(\d{2})$/) {
		my $seed = timelocal($6,$5,$4,$3,$2-1,$1+2000);
		return $seed;
	}
	return 0;
}

=head3 _printf (I<format>,I<@array>)

Works just like C<printf> except has a built-in check for C<-verbose>.

=cut

sub _printf {
	my $self = shift;

	return 0 unless $self->{-verbose};

	return printf @_;
}

=head1 HISTORY

20120313 - v1.0 - Created.

20120314 - v1.0.1 - Rename, add PODs symlink.

=head1 AUTHOR

This module by Paul Pham.

=head1 COPYRIGHT AND LICENSE

Copyright 2012 by Paul Pham

This program and library is free software;
you can redistribute it and/or modify it under the same terms as Perl itself.

=cut

1;
