#!/usr/bin/perl

use strict;
use warnings;
use 5.008005;
use Pod::Usage qw/pod2usage/;
use Getopt::Long;
Getopt::Long::Configure ("no_ignore_case");

use constant OUTSIDE => 0;
use constant INSIDE => 1;
use constant OK => 0;
use constant WARNING => 1;
use constant CRITICAL => 2;
use constant UNKNOWN => 3;

# copy from Nagios::Plugin
my $value_n = qr/[-+]?[\d\.]+/;
my $value_re = qr/$value_n(?:e$value_n)?/;

my $host;
my $community;
my $snmp_version = '2c';
my $warning_arg = 0;
my $critical_arg = 0;
my $timeout = 10;
my $disklabel;

GetOptions(
    "h|help"   => \my $help,
    "H|hostname=s" => \$host,
    "C|community=s" => \$community,
    "P|protocol=s" => \$snmp_version,
    "w|warning=s" => \$warning_arg,
    "c|critical=s" => \$critical_arg,
    "t|timeout=i" => \$timeout,
    "d|disk=s" => \$disklabel,
) or pod2usage(-verbose=>1,-exitval=>UNKNOWN);
pod2usage(-verbose=>1,-exitval=>CRITICAL) if !$host || !$disklabel || !$community;
pod2usage(-verbose=>2,-exitval=>OK) if $help;

my $warning = parse_range_string($warning_arg);
if ( !$warning ) {
    print "CRITICAL: invalid range definition '$warning_arg'\n";
    exit CRITICAL;    
}
my $critical = parse_range_string($critical_arg);
if ( !$critical ) {
    print "CRITICAL: invalid range definition '$critical_arg'\n";
    exit CRITICAL;    
}

my $getwalk = sub {
    my ($oid) = @_;
    local $/;
    open(my $fh, '-|', 'snmpwalk','-v',$snmp_version, '-c', $community, '-t', $timeout, $host, $oid) || die $!;
    my $data = <$fh>;
    return $data;
};

my $snmpget = sub {
    my @oid = @_;
    local $/;
    open(my $fh, '-|', 'snmpget','-v',$snmp_version, '-c', $community, '-t', $timeout, $host, @oid) || die $!;
    my $data = <$fh>;
    return $data;
};


my $descr;
eval {
    $descr = $getwalk->('hrStorageDescr');   
};

if ( $@ ) {
    print "CRITICAL: $@";
    exit CRITICAL;
}

my $disk_index;
for my $l ( split /\n/, $descr ) {
    if ( $l =~ m!^HOST-RESOURCES-MIB::hrStorageDescr.(\d+) = STRING: (.+)$! ) {
        if ( $2 eq $disklabel ) {
            $disk_index = $1;
            last;
        }
    }
}

if ( ! defined $disk_index ) {
    print "CRITICAL: storage not found. disk: $disklabel";
    exit CRITICAL;
}

my $used_table;
eval {
    $used_table = $snmpget->(map { $_.'.'.$disk_index } qw/hrStorageUsed hrStorageSize/);
};
if ( $@ ) {
    print "CRITICAL: $@";
    exit CRITICAL;
}


my %used;
for my $l ( split /\n/, $used_table ) {
    if ( $l =~ m!^HOST-RESOURCES-MIB::(hrStorageSize|hrStorageUsed).(\d+) = INTEGER: (.+)$! ) {
        $used{$1} = $3;
    }
}

my $val = int( $used{hrStorageUsed}/$used{hrStorageSize}*100);

# range check
if ( check_range($critical, $val) ) {
    printf "SNMP_STORAGE CRITICAL: disk:%s *%s\n", $disklabel, $val;
    exit CRITICAL;
}

if ( check_range($warning, $val) ) {
    printf "SNMP_STORAGE WARNING: disk:%s *%s\n", $disklabel, $val;
    exit WARNING;
}

printf "SNMP_STORAGE OK: disk:%s *%s\n", $disklabel, $val;
exit OK;

# copy from Nagios::Plugin
sub parse_range_string {
    my ($string) = @_;
    my $valid = 0;
    my %range = (
        start => 0, 
        start_infinity => 0,
        end => 0,
        end_infinity => 1,
        alert_on => OUTSIDE
    );
    $string =~ s/\s//g;  # strip out any whitespace
    # check for valid range definition
    unless ( $string =~ /[\d~]/ && $string =~ m/^\@?($value_re|~)?(:($value_re)?)?$/ ) {
        return;
    }

    if ($string =~ s/^\@//) {
        $range{alert_on} = INSIDE;
    }

    if ($string =~ s/^~//) {  # '~:x'
        $range{start_infinity} = 1;
    }
    if ( $string =~ m/^($value_re)?:/ ) {     # '10:'
       my $start = $1;
       if ( defined $start ) {
           $range{start} = $start + 0;
           $range{start_infinity} = 0;
       }
       $range{end_infinity} = 1;  # overridden below if there's an end specified
       $string =~ s/^($value_re)?://;
       $valid++;
   }
    if ($string =~ /^($value_re)$/) {   # 'x:10' or '10'
        $range{end} = $string + 0;
        $range{end_infinity} = 0;
        $valid++;
    }

    if ($valid && ( $range{start_infinity} == 1 
                 || $range{end_infinity} == 1 
                 || $range{start} <= $range{end}
                 )) {
        return \%range;
    }

    return;
}

# Returns 1 if an alert should be raised, otherwise 0
sub check_range {
    my ($range, $value) = @_;
    my $false = 0;
    my $true = 1;
    if ($range->{alert_on} == INSIDE) {
        $false = 1;
        $true = 0;
    }
    if ($range->{end_infinity} == 0 && $range->{start_infinity} == 0) {
        if ($range->{start} <= $value && $value <= $range->{end}) {
            return $false;
        }
        else {
            return $true;
        }
    }
    elsif ($range->{start_infinity} == 0 && $range->{end_infinity} == 1) {
        if ( $value >= $range->{start} ) {
            return $false;
        }
        else {
            return $true;
        }
    }
    elsif ($range->{start_infinity} == 1 && $range->{end_infinity} == 0) {
        if ($value <= $range->{end}) {
            return $false;
        }
        else {
            return $true;
        }
    }
    return $false;
}

__END__


=encoding utf8

=head1 NAME

check_snmp_hrstorage.pl - nagios plugin for checking disk uasge via hrStorageTable

=head1 SYNOPSIS

  usage: check_smmp_hrstorage.pl -H host -P snmp version -C public -w 80 -c 95 -t 10 -d /

=head1 DESCRIPTION

check_snmp_hrstorage.pl is nagios plugin to check disk uasge via hrStorageTable

=head1 ARGUMENTS

=over 4

=item -h, --help

Display help message

=item -H, --hostname=STRING

Host name or IP Address

=item -P, --protocol= STRING

SNMP version (1|2c|3)

=item -d, --disk=STRING

mount Path for check usage

=item -w, --warning=THRESHOLD

Warning threshold range

See L<http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT> for THRESHOLD format and examples

=item -c, --critical=THRESHOLD

Critical threshold range

=item -t, --timeout=INTEGER

Seconds before connection times out.

=back


=head1 INSTALL

just copy this script to nagios's libexec directory.

  $ curl https://raw.github.com/kazeburo/check_snmp_hrstorage/master/check_snmp_hrstorage.pl > check_snmp_hrstorage.pl
  $ chmod +x check_snmp_hrstorage.pl
  $ cp check_snmp_hrstorage.pl /path/to/nagios/libexec

=head1 AUTHOR

Masahiro Nagano E<lt>kazeburo@gmail.comE<gt>

=head1 LICENSE

Copyright (C) Masahiro Nagano

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

