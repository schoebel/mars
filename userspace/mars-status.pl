#!/usr/bin/perl -w
#
# $Id$
# $Author$ $Date$
# last update at Fr 27. Jan 12:59:55 CET 2012 by joerg.mann@1und1.de

# TODO:
# version marsadm
# check replay-blocks
# check division zero
# check deutsch/englich
# add todo-global delete-logfiles


###
use warnings;
use strict;
use English;
use Term::ANSIColor;


### defaults
my $version       = "0.067k";
my $alife_timeout = "99";	# sec
my $is_tty 	  = 0;
my $mars_dir      = '/mars';
my $himself       = `uname -n` or die "cannot determine my network node name\n";
chomp $himself;


### ARGV
# Todo: @argv
my $OptionList    = shift;
my $OptionRes     = shift;
if ( !$OptionList ) {
	$OptionList = "small";
}

### figure out TTY
my $tty = readlink '/dev/stdout';
while ( my $temp = readlink $tty ) {
	$tty = $temp;
}
if ( $tty =~ /^\/dev\/pts\// ) {
	$is_tty = 1;
} elsif ( $tty =~ /^\/dev\/tty/ ) {
	$is_tty = 1;
}

#########################################################################################
### subs
sub check_link {
	my $dir = shift;
	my $result = readlink $dir;
	if ( !$result ) {
		return 0;
	} else {
		return $result;
	}
}

### print color
sub print_warn {
	my $text  = shift;
	my $color = shift;
	print color "$color" if ( $is_tty );
	print "$text";
	print color 'reset' if ( $is_tty );
}

### read links
sub convert_link {
	my $link = shift;
	$link = check_link "$link";
	if ( ( !$link ) || ( $link eq 0 ) ) {
	        print_warn "off", 'red';
	} else {
		print_warn "on", 'green';
	}
	return $link;
}

#########################################################################################
### sub display resource-partner
sub display_partner {
	my %p 			= @_;
	my $PRes  		= $p{ressource};
	my $PName 		= $p{nodename};
	my $PSize 		= $p{ressource_size};
	my $ref_ResPartner  	= $p{res_partner};
	my $ref_ResInReplay 	= $p{res_inreplay};
	my $ref_ResInSync   	= $p{res_insync};
	my $ref_AULogfile	= $p{res_AULogfile};

        my $PStatus  = check_link "$mars_dir/$PRes/primary";
        my $PDevice  = check_link "$mars_dir/$PRes/device-$PName";  
        my $Ljoined  = check_link "$mars_dir/$PRes/device-$himself";
	
        ### status
        if ( $PStatus eq $PName ) {   
               	print_warn "as Primary, ",'blue';
        } else {
        	if ( $PDevice eq 0 ) {
                	print_warn "not joined, ",'red';
        	} else {
               	        print_warn "as Secondary, ",'blue';
		}
	}	
	

	### alive
	my @PAlive = lstat("$mars_dir/alive-$PName");
	if ( !$PAlive[9] ) { $PAlive[9]=0 };
	my $PAlive =  time()- $PAlive[9] - $alife_timeout;
	if ( $PAlive > 1  ) {
	        print_warn "Status: unknown (last message before $PAlive sec) !!!\n", 'red';
	} else {
		print_warn "Status: connected\n",'blue'; 
	}


        ### device
        # joined  ?
        if ( $PDevice eq 0 ) {
                if ( $OptionList eq "long" ) { print_warn "   -> Resource is not joined to this node\n", 'red'; }
                return; 
        }
        if ( $OptionList eq "long" ) {
                print "\tDevice  : ".check_link "$mars_dir/$PRes/data-$PName";
                print ", used as $PDevice";
                
                # check mountpint
                if ( $himself eq $PName ) {
                	my $PUDevice = "/dev/mars/$PDevice";
               		#print " and ";
                	if ( stat( $PUDevice) ) {
				open my $fh, '<', '/proc/mounts' or die $!;
				$PUDevice = ( grep { /^$PUDevice / } <$fh> )[0];
                		if ( $PUDevice ) {
                			$PUDevice = ( split / /, $PUDevice )[1];
	                		print_warn " and mountet as $PUDevice\n",'blue';
				} else {
					print_warn "\n\t---> TODO: enable to mount\n",'green';
				}
			} else {
	                	print_warn "\n\t---> TODO: unable to mount, Device is Secondary or mars is starting ...\n",'red';			
			}
		} else {
			print "\n";
		}
        }
        $$ref_ResPartner++;


	### logfile
	my @PLogFile = split (',', check_link "$mars_dir/$PRes/replay-$PName" );
	my @PLogLink = split ("-", $PLogFile[0]);
	my $PLogName = "$PLogLink[0]-$PLogLink[1]";
	my $PLogSize  = -s "$mars_dir/$PRes/$PLogFile[0]";
	if (( !$PLogSize ) || ( $PLogSize eq 0 )) { $PLogSize = 0.0001; }
	if ( $OptionList eq "long" ) {
		printf "\tLogfile : %s with %s bytes (%.3fGB) received\n", $PLogName, $PLogSize, ( $PLogSize/1024/1024/1024 );
		if ( $Ljoined eq "0" || $PLogSize eq "0.0001" ) {
			print_warn "\t---> TODO: Logfile inactive or empty (Size: $PLogSize)\n", 'red';
		}
		if ( ( $ref_AULogfile ) && !($PLogName eq $ref_AULogfile) ) {
			print_warn "\t---> TODO: Logfile Version not actual = ($PLogName ! $ref_AULogfile)\n", 'red';
		}
	}
	

	### replay
	my $RStatus = ( $PLogFile[1] / $PLogSize ) * 100;
	if ( $Ljoined eq "0" || $PLogSize eq "1" ) { $RStatus = 0; }
	$$ref_ResInReplay = $RStatus;
	if ( $OptionList eq "long" ) {
		printf "\tReplayed: %s bytes (%.3fGB) replayed, Todo %d (%.3fGB) = ", 
			$PLogFile[1], ( $PLogFile[1]/1024/1024/1024 ), 
			$PLogFile[2], ( $PLogFile[2]/1024/1024/1024 );
		$RStatus = sprintf("%.2f", $RStatus);
		if ( $RStatus < 1) {
			print_warn "$RStatus%\n\t---> TODO: Replay not started, Logfile inactive or empty ?\n", 'red';
		} elsif ( $RStatus < 100) {
			print_warn "$RStatus%\n\t---> TODO: Replay in progress = ($RStatus% < 100.00%)\n", 'red';
		} else {
			print_warn "$RStatus%\n", 'green';
		}			
	}	
	

	### sync
	my $PSyncsize = check_link "$mars_dir/$PRes/syncstatus-$PName";
	my $SStatus = ( $PSyncsize / $PSize * 100);
	$$ref_ResInSync = $SStatus;
	if ( $OptionList eq "long") {
		printf "\tSync    : %s bytes (%.3fTB) synced = ", $PSyncsize, ( $PSyncsize/1024/1024/1024/1024);
                $SStatus = sprintf("%.2f", $SStatus);
                if ( $SStatus < 100) {
                        print_warn "$SStatus%\n\t---> TODO: Sync in progress = ($SStatus% < 100.00%)\n", 'red';
		} else {
			print_warn "$SStatus%\n", 'green';
                }
	}

	
	if ( $OptionList eq "long") {
        	### actual
        	my $ActStatus  = check_link "$mars_dir/$PRes/actual-$PName/is-primary";
        	if ( $ActStatus eq 1 ) {
	               print "\tActual  : Status Primary, used Device="; convert_link "$mars_dir/$PRes/actual-$PName/device-$PDevice";
	               print "\n";
        	} else {
                       print "\tActual  : Status Secondary, Syncstatus="; convert_link "$mars_dir/$PRes/actual-$PName/copy-syncstatus-$PName";
                       print ", Logfileupdate="; convert_link "$mars_dir/$PRes/actual-$PName/logfile-update";
                       print "\n";
                }

        	### switch
        	print "\tSwitch  : Attach="; convert_link "$mars_dir/$PRes/todo-$PName/attach";
        	print ", Connect="; convert_link "$mars_dir/$PRes/todo-$PName/connect";
        	print ", Sync="; convert_link "$mars_dir/$PRes/todo-$PName/sync";
        	print ", AllowReplay="; convert_link "$mars_dir/$PRes/todo-$PName/allow-replay";
        	print "\n";
        }
        return $PLogName;
}


#########################################################################################
###
sub check_logfile {
        my $LResource 	= shift;
        my $LPartner  	= shift;
	my $oldEqual 	= 0;
	my $LogCount	= 0;
	print_warn "   -> History Replay/Status\n",'blue';

	my @logfile 	= <$mars_dir/$LResource/log*>;
	foreach my $logfile (@logfile) {
		my $LVersion    = $logfile;
		$LVersion       =~ s/^.*log-([0-9]+)-.*$/$1/;
		my $LogStatus   = check_link "$logfile";
		my $allEqual    = 1;
		if ( $LogStatus eq 0 ) { 
			# info to old logfiles (old loop) ...
			if ( $oldEqual eq 1 ) {
                                print_warn "\t\t---> TODO: logfiles has all equal Sizes and Checksums, can be deleted?\n",'green';
			}

			# found logfile
			my $OldCheck;
			my $OldSize;
			my $LogSize = -s "$logfile";
			print "\tLogfile Version: $LVersion - Size: $LogSize\n";

			# check other ...
			my @LVersion = <$mars_dir/$LResource/version-$LVersion*>;
			foreach my $LVersion (@LVersion) {
				my @LogDetail = split (',', check_link "$LVersion" );
				my $LogServer = $LVersion;
				$LogServer    =~ s/.*[0-9]-//;
				$LogCount++;
				print "\t\tSource: $LogServer, Check: $LogDetail[0], Size: $LogDetail[2], Todo: $LogDetail[3] blocks\n";
				# Initial Values
				if ( !defined $OldCheck ) {
				      # new
				      $OldCheck = $LogDetail[0];
                                      $OldSize  = $LogDetail[2];
                                      $allEqual = 1; 
                                } elsif (!(( $LogDetail[0] eq $OldCheck ) and ( $LogDetail[2] eq $OldSize ))) { 
				      # not same
				      $allEqual = 0;
				      if ( !($LogDetail[0] eq $OldCheck) && ($LogDetail[2] eq $OldSize) ) {
				      		print_warn "\t\t---> TODO: check logfiles has not equal Checksums and same size !!!\n",'red';
			      		} else {
			      			print_warn "\t\t---> TODO: check logfiles has not equal Checksums and different size ???\n",'blue';
					}
                                } else {
				      # same
				      $allEqual = 1;
                                }

                                # check bad values
				if ( $LogDetail[3] < 0 ) {
					print_warn "\t\t---> TODO: Found bad values ($LogDetail[3])it's ok ???\n", 'red';
				}
			}
			if ( $allEqual eq 1 ) {
                                $oldEqual = 1;
			} else {
				$oldEqual = 0;
			}
			# check Count Logfiles
                        if ( !($LogCount eq $LPartner) ) {
                        	print_warn "\t\t---> TODO: Count of Logfiles different (have:$LPartner found:$LogCount)\n", 'red';
                        	$oldEqual = 0;
			}
			$LogCount=0;
                }
	}
}

#########################################################################################
### read mars infos
my %mars_info;
open ( my $lsmod_handle,'-|','lsmod | grep mars' ) || die "blub ... $!";
if (!<$lsmod_handle>) {
	print_warn "Module Mars not running\n",'red';
	exit 1;
}

open ( my $modinfo_handle, '-|', 'modinfo mars' ) || die "cannot run modinfo mars: $!";
while ( my $line = <$modinfo_handle> ) {
	chomp $line;
	my ( $key, $value) = split /: +/, $line;
	if ( $value) {
		$mars_info{$key} = $value;
	}
}

if ( $mars_info{author} eq "") {
	print_warn "Module Mars not running\n",'red';
	exit 1;
}

# status
print_warn "MARS Status - $himself, $version",'blue';
if ( $OptionList ) { print_warn ", Listmodus $OptionList",'blue'; }
if ( $OptionRes  ) { print_warn ", Ressource $OptionRes",'blue'; }
print "\n";

# marsadm
my $MAVersion = '/usr/local/bin/marsadm';
open my $Mfh, '<', "$MAVersion" or die $!;
$MAVersion = ( grep { /^# \$Id: / } <$Mfh> )[0];
$MAVersion = ( split / /, $MAVersion )[2];
print_warn "MARS Admin  - $MAVersion\n",'blue';

# module
print_warn "MARS Module - $mars_info{version}\n",'blue';

# kernel
my $KVersion = '/proc/version';
open my $Kfh, '<', "$KVersion" or die $!;
$KVersion = ( grep { /^Linux/ } <$Kfh> )[0];
$KVersion = ( split / /, $KVersion )[2];
print_warn "MARS Kernel - $KVersion\n",'blue';

print "-------------------------------------------------------------------------------\n";

#########################################################################################
### check system error's
### diskfull
my @diskfull = glob("$mars_dir/rest-space-*");
if ( @diskfull ) { 
	foreach ( @diskfull) {
               	my $diskfullspace     = check_link "$_";                        
               	my $diskfullsystem = $_;                
               	$diskfullsystem    =~ s!/mars/rest-space-!!;
               	if ( $diskfullspace < 1 ) {
               		$diskfullspace = sprintf ("%.2f", $diskfullspace / 1024 );
               		if ( $diskfullsystem eq $himself ) {
               			print_warn "\n-> ERROR ! Local Partition $mars_dir full ($diskfullspace kb Limit) !!! mars is stopping !!!\n\n", "red";
               		} else {
               			print_warn "\n-> WARNING ! Remotesystem $diskfullsystem have mars-disk full ($diskfullspace kb Limit) !!!\n\n", "red";
               		}
		}
	}
}
              	
#########################################################################################
### check resources
opendir my $dirhandle, $mars_dir or die "Cannot open $mars_dir: $!";
my @resources = grep { /^res/ && -d "$mars_dir/$_" } readdir $dirhandle;
if ( !@resources ) {
        print_warn "---> no resources found\n", 'red';
        exit;
}


foreach my $res (@resources) {
	my $ResPartner   = 0;
	my $ResInReplay  = 0;
	my $ResInReplayE = 0;
	my $ResInSync    = 0;
	my $ResInSyncE   = 0;
	my $res_name     = $res;
	$res_name        =~ s/^resource-//;
	if ( $OptionRes ) {
		if (!( $OptionRes eq $res_name)) {
			next;
		}
	}
	my $res_size     = check_link "$mars_dir/$res/size";
        if ( $res_size eq 0 ) { $res_size = 1 };
        my $res_tbsize   = ( $res_size) / 1024 / 1024 /1024 / 1024;
        my $res_master   = check_link "$mars_dir/$res/primary";
        if ( $res_master eq 0 ) { $res_master = "unknown" };
        print color 'bold' if ( $is_tty );
        printf  "-> check resource %s, with %d bytes (%.3fTB), Primary Node is %s\n", $res_name, $res_size, $res_tbsize, $res_master;
        print color 'reset' if ( $is_tty );
	

	### hin self
	print_warn "   -> local node ($himself) ",'blue';
	my $ActualUsedLogfile = display_partner(
		ressource	=> $res,
		nodename	=> $himself,
		ressource_size	=> $res_size,
		res_partner	=> \$ResPartner,
		res_inreplay    => \$ResInReplay,
		res_insync      => \$ResInSync,
		res_AULogfile   => "",
	);
	$ResInReplayE = $ResInReplay;
	$ResInSyncE   = $ResInSync;

	# not joined ...
	if ( $ResPartner eq 1) {
		### partners
		opendir my $server_dh, "$mars_dir/$res" or die "Cannot open $mars_dir/$res: $!";
		my @servers = grep { /^data/ && readlink "$mars_dir/$res/$_" } readdir $server_dh;
		@servers    = sort (@servers);
		foreach my $partner (@servers) {
			$partner  =~ s/^data-//;
			if ( $partner eq $himself ) { next; }
			print_warn "   -> remote node ($partner) ", 'blue';
			display_partner(
				ressource	=> $res,
				nodename	=> $partner,
				ressource_size	=> $res_size,
				res_partner	=> \$ResPartner,
				res_inreplay    => \$ResInReplay,
				res_insync      => \$ResInSync,
				res_AULogfile   => $ActualUsedLogfile,
				);
		}
		$ResInReplayE = $ResInReplayE + $ResInReplay;
		$ResInSyncE   = $ResInSyncE + $ResInSync;
	}

	
	### modus
        if ( $ResPartner eq 0) { 
            if ( $OptionList eq "long" ) { print_warn "   -> modus for $res_name is remote ($ResPartner nodes)\n",'blue'; }
        } elsif ( $ResPartner eq 1 ) { 
	    if ( $OptionList eq "long" ) { print_warn "   -> modus for $res_name is standalone ($ResPartner node)\n",'blue'; }
        } else {
	    print_warn "   -> modus for $res_name is cluster ($ResPartner nodes), ",'blue';
            $ResInReplayE = sprintf("%.2f", $ResInReplayE / $ResPartner );
            $ResInSyncE   = sprintf("%.2f", $ResInSyncE / $ResPartner );
            if ( $ResInReplayE eq "100.00" ) {
        	print_warn "in replay ($ResInReplayE%),", 'green';
            } elsif ( $ResInReplayE eq "0.00" ) {
        	print_warn "inaktiv ($ResInReplayE%),", 'red';
            } else {
	        print_warn "not in replay ($ResInReplayE%),", 'red';
            }
	    if ( $ResInSyncE eq "100.00" ) {
		print_warn " in sync ($ResInSyncE%)\n", 'green';
	    } else {
	        print_warn " not in sync ($ResInSyncE%)\n", "red";
	    }
        }


        ### history
        if ( $OptionList eq "long" ) { check_logfile( $res, $ResPartner ); }
}
print color 'reset';
exit;
	
