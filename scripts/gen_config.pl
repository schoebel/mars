#!/usr/bin/perl

use strict;
use warnings;

use 5.010;

use Data::Dumper;

my $DEBUG = 0;

##
## Parse Kconfig from STDIN
##

my $option;
my $type;
my $depends;
my $value;
my @default;
my %setByEnv;

while (my $line = <STDIN>) {
    if ($line =~ /^config\s+(\w+)\W*$/) {
        $option = $1;
        $setByEnv{$option} = $ENV{$option}  if exists $ENV{$option};
        printf STDERR "OPTION: %s\n", $option if $DEBUG;
        printf STDERR "--> ENV: %s='%s'\n", $option, $setByEnv{$option} if $DEBUG && exists $ENV{$option};
    }
    elsif ($line =~ /^\s+(tristate|bool|int|string)\s+.*$/) {
        $type = $1;
        printf STDERR "--> TYPE: %s\n", $type if $DEBUG;
    }
    elsif ($line =~/^\s+depends\s+on\s+(.*)$/) {
        $depends = ($option ne 'MARS') ? $1 : '';
        printf STDERR "--> DEPENDS: %s\n", $depends if $DEBUG;
    }
    elsif ($line =~ /^\s+default\s+(.*)$/) {
        if ($option eq 'MARS') {
            $value = 'y';
            printf STDERR "--> DEFAULT: y (OVERRIDDEN by script)\n" if $DEBUG;
        }
        else {
            $value = $1;
            printf STDERR "--> DEFAULT: %s\n", $value if $DEBUG;
        }
        push @default, {
            option => $option,
            type => $type,
            depends => $depends,
            value => $value,
        } if $option;
    }
    elsif ($line =~ /^\s+---help---\s+$/) {
        # ignore lines after this by unsetting $option
        undef $option;
        # Kconfig syntax allows to have directives after the help section,
        # but we do not use this freedom here, for simplicity.
    }
}

print STDERR Dumper(\@default) if $DEBUG >= 2;


##
## Print the header
##

print qq%
#ifndef MARS_CONFIG_H
#define MARS_CONFIG_H

/*
 * Module default settings from Kconfig
 *
 * If the module is built as an external module, this file provides
 * reasonable default settings for configuration variables CONFIG_*.
 * The defaults are extracted from Kconfig. If you want to change a
 * setting, please edit Kconfig directly and regenerate this file.
 * 
 * This file was auto-generated with $0
 * -- DO NOT EDIT MANUALLY --
 */

#ifndef CONFIG_MARS_HAVE_BIGMODULE
#define CONFIG_MARS_HAVE_BIGMODULE
#endif
%;

##
## Print option defaults
##

foreach my $opt (@default) {

    my $optname = $opt->{option};
    my $optval = $opt->{value};

    if (exists $setByEnv{$optname}) {
        print qq%
/* CONFIG_$optname overridden by ENVIRONMENT */%;
        $optval = $setByEnv{$optname};
	$opt->{value} = $optval;
    }

    if (!defined($optname) || !defined($optval)) {
        printf(STDERR "SKIPPED option due to missing parameters: optname=%s optval=%s\n",
               $optname||'', $optval||'');
        next;
    }

    if ($opt->{depends}) {
        my @deps = grep { $_->{option} eq $opt->{depends} } @default;
        if (scalar @deps && $deps[0]->{value} eq 'n') {
            print qq%
/* CONFIG_$optname is unset (depends on $deps[0]->{option}, which is unset) */
%;
            next;
        }
    }

    given ($opt->{type}) {

        when ('tristate') {
            # ignore tristate
        }

        when ('bool') {
            if ($optval eq 'n') {
                print qq%
/* CONFIG_$optname is unset */
%;
            }
            else {
                print qq%
#ifndef CONFIG_$optname
#define CONFIG_$optname 1
#endif
%;
            }
        }

        when (['int', 'string']) {
            print qq%
#ifndef CONFIG_$optname
#define CONFIG_$optname $optval
#endif
%;
        }

    }

}

print qq%

#endif  /* MARS_CONFIG_H */
%;
