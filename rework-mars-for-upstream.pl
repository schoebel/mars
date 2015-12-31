#!/usr/bin/perl -w

## HACK: for singular use only!
##
## convert github.com/schoebel/mars to in-tree kernel version
## for upstream submission

use strict;
use English;
use warnings;

use Text::Tabs;
use Tie::IxHash;

## PARAMETERS: adjust to your needs

# MARS source parameters
my $mars_master_branch   = "WIP-BASE";
my $mars_slave_branch    = "WIP-PORTABLE";
my $mars_nonport_branch  = "WIP-PROPOSE-UPSTREAM";
my $mars_src             = "kernel";

# target kernel parameters
my $kernel_dir           = "/home/schoebel/linux-next";
my $kernel_master_branch = "WIP-UPSTREAM-BASE";
my $kernel_slave_branch  = "WIP-MARS";
my $kernel_trail_branch  = "WIP-TRAILING-PATCHES";
my $kernel_src           = "drivers/staging/mars";
# I'm unsure where this should go to.
my $kernel_incl_prefix   = "$kernel_src/";
my $kernel_incl_lib      = "include/linux/brick";
#my $kernel_incl_lib      = "${kernel_incl_prefix}include/brick";
my $kernel_incl_brick    = "include/linux/brick";
#my $kernel_incl_brick    = "${kernel_incl_prefix}include/brick";
my $kernel_incl_xio      = "include/linux/xio";
#my $kernel_incl_xio      = "${kernel_incl_prefix}include/xio";
my $kernel_incl_light    = "include/linux/mars_light";
#my $kernel_incl_light    = "${kernel_incl_prefix}include/mars_light";
my $kernel_src_lib       = "$kernel_src/lib";
my $kernel_src_brick     = "$kernel_src";
my $kernel_src_xio       = "$kernel_src/xio_bricks";
my $kernel_src_light     = "$kernel_src/mars_light";

# checkpatch parameters
my $checkpatch           = "$kernel_dir/scripts/checkpatch.pl";
my $checkpatch_ignore    = "LONG_LINE,LONG_LINE_STRING,FILE_PATH_CHANGES,PREFER_PR_LEVEL";
my $max_line_length      = 120;

#####################################################################

my $delta_mode = 0;

sub pre_commit
{
  system "find $mars_src/ -name '*.tmp' | while read x; do y=\"\$(echo \"\$x\" | sed 's/\.tmp\$//')\"; mv \"\$x\" \"\$y\"; done" and die;
}

sub commit
{
  my ($msg, $ignore) = @_;
  pre_commit();
  if (!$delta_mode) {
    system "git commit -a --allow-empty -m '$msg'" and
      (defined($ignore) or die "commit '$msg'\n");
  }
}

#####################################################################

my %moves = ();

sub rework_txt
{
  my ($path, $this) = @_;
  open IN, "< $path" or die "cannot open '$path'";
  local $/;
  my $text = <IN>;
  close(IN);

  $text =~ s,^(?:/[*/]|\#\#)\s*remove_${this}(?:[^\n]*?\n)*?(?:^(?:/[*/]|\#\#)\s*else_${this}[^\n]*?\n(.*?\n)|)^(?:/[*/]|\#\#)\s*?end_remove_${this}[^\n]*?\n,$1=~s;^(?:/[*/]|\#\#) *|\s*[*/]/$;;mgsr,mgsie;

  my $done = "";
  while ($text =~ m,^(?:/[*/]|\#\#)\s*move_$this\s*(?:to\s*)([a-z]+)\s*\n(.*?)\n(?:/[*/]|\#\#)\s*end_move_$this.*?\n,msip) {
    $done .= $PREMATCH;
    $text = $POSTMATCH;
    $moves{$1} = $2;
  }

  open OUT, "> $path.tmp" or die;
  print OUT $done . $text;
  close(OUT);
}

sub apply_moves
{
  my ($path) = @_;
  open IN, "< $path.tmp" or die;
  local $/;
  my $text = <IN>;
  close(IN);
  my $done = "";
  while ($text =~ m,^//\s*place\s*([a-z]+)\s*\n,mip) {
    my $place = $1;
    $done .= $PREMATCH;
    $text = $POSTMATCH;
    die "unknown place '$place'" unless defined($moves{$place});
    print "moving '$place'\n";
    $done .= $moves{$place};
    undef $moves{$place};
  }
  open OUT, "> $path.tmp" or die;
  print OUT $done . $text;
  close(OUT);
}

sub check_places
{
  my ($path) = @_;
  open IN, "< $path.tmp" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  if ($text =~ m,^//\s*place\s*([a-z]+)\s*\n,mip) {
    die "unused place '$1' -- check or remove this!\n";
  }

  if ($text =~ m,^//\s*(end_)?remove_[a-z]+,mi) {
    die "stray '.*remove_.*' !\n";
  }
}

sub rework_all
{
  my @paths = ("$mars_src/Makefile", `find $mars_src -name "*.[ch]"`);
  foreach my $path (@paths) {
    chomp $path;
    print "--- phase1 rework $path\n";
    rework_txt($path, "this");
  }
  foreach my $path (@paths) {
    chomp $path;
    print "--- phase2 moving to $path\n";
    apply_moves($path);
  }
  foreach my $path (@paths) {
    chomp $path;
    print "--- phase3 checking $path\n";
    check_places($path);
  }
  my $count = 0;
  foreach my $place (keys %moves) {
    warn "----> missing place '$place'\n";
    $count++;
  }
  die "places are missing.\n" if $count;
  pre_commit();
}

#####################################################################

sub attribute_txt
{
  my ($path) = @_;
  open IN, "< $path" or die;
  open OUT, "> $path.tmp" or die;
  while (my $line = <IN>) {
    $line =~ s/__attribute__\s*\(\(\s*format\s*\(\s*printf\s*,\s*([^,]*?),\s*(.*?)\)\s*\)\)/__printf($1, $2)/g;
    $line =~ s/__FUNCTION__/__func__/g;
    print OUT $line;
  }
  close(IN);
  close(OUT);
}

sub attribute_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- correct attributes $path\n";
    attribute_txt($path);
  }
  pre_commit();
}

#####################################################################

sub includes_txt
{
  my ($path) = @_;
  open IN, "< $path" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  $text =~ s:\#\s*include\s*\<asm/(atomic|uaccess)\.h\>:\#include <linux/$1.h>:msg;

  open OUT, "> $path.tmp" or die;
  print OUT $text;
  close(OUT);
}

sub includes_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- rename include files $path\n";
    includes_txt($path);
  }
  pre_commit();
}

#####################################################################

sub statics_txt
{
  my ($path) = @_;
  open IN, "< $path" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  $text =~ s:^([ \t]*static [^\n=]+?) *= *(0|NULL|false|\{\s*\});((\s*/[^\n]+)?)$:$1;$3:msg;
  $text =~ s:^(\w+ [\w\*\s]+?) *= *(0|NULL|false); *(/.*?)?$:$1;:msg;

  open OUT, "> $path.tmp" or die;
  print OUT $text;
  close(OUT);
}

sub statics_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- rename include files $path\n";
    statics_txt($path);
  }
  pre_commit();
}

#####################################################################

sub returns_txt
{
  my ($path) = @_;
  open IN, "< $path" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  if ($text =~ s:^(\s*)return;\s*$:${1}goto out_return;:msg) {
    $text =~ s/(goto out_return;.*?)^}$/${1}out_return:;\n}/msg;
    $text =~ s/(^out_return:;\n)+/out_return:;\n/msg;
    $text =~ s/(return [^;\n]+;\n((\/|\#|\s*(return|goto))[^\n]*\n)*)^out_return:;\n/${1}/msg;
  }

  open OUT, "> $path.tmp" or die;
  print OUT $text;
  close(OUT);
}

sub returns_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- replace return in void functions $path\n";
    returns_txt($path);
  }
  pre_commit();
}

#####################################################################

sub macros_txt
{
  my ($path) = @_;
  open IN, "< $path" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  $text =~ s:^\#\s*define\s+([a-zA-Z_0-9]+[ \t]+)([^\s0-9/\\\n][^/\\\n]+?[0-9][^/\\\n]+?[^)"\n])\n:\#define $1($2)\n:msg;

  open OUT, "> $path.tmp" or die;
  print OUT $text;
  close(OUT);
}

sub macros_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- fix #define paranthese $path\n";
    macros_txt($path);
  }
  pre_commit();
}

#####################################################################

sub braces_txt
{
  my ($path) = @_;
  open IN, "< $path" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  # Remove empty if-statements resulting from previous elimination steps.
  # CAVEAT: hopefully they contain no side effects! CHECK BY HAND!
  $text =~ s:(^|\})\s*else\s*\{\s*\}:$1:msg;
  $text =~ s:^\s*if\s*\([^{}\n]*?\)\s*\{\s*\}\s*?\n::msg;

  # Only _after_ that, remove superfluos braces.
  # Personally, I find it better to keep them, because they make code
  # much more rubust against insertion / deletion of statements.
  # IMHO, this is more valuable than readability.
  # But I have to meet the upstream requirements.
  my $done = "";
  while ($text =~ m/^(\s*(?:if|for|while))\s+\(([^\n]*?)\)\s*?\{\s*?\n([^;{}\n]*;)\s*?\n(\s*)\}(\s*?\n|\s*else\s*\{\s*?\n[^;{}\n]*;[^;{}\n]*?\n\s*\})/msp) {
    $done .= "$PREMATCH$1 ($2)\n$3\n";
    my $inter = $4;
    $text = $5 . $POSTMATCH;
    if ($text =~ m:^\s*else\s*\{\s*?\n([^;\n]*;)\s*?\n\s*\}\s*\n:msp) {
      $done .= "${inter}else\n$1\n";
      $text = $POSTMATCH;
    } else {
      $text =~ s:^\s*?\n::;
    }
  }

  open OUT, "> $path.tmp" or die;
  print OUT $done . $text;
  close(OUT);
}

sub braces_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- remove unncecessary braces $path\n";
    braces_txt($path);
  }
  pre_commit();
}

#####################################################################

sub spaces_txt
{
  my ($path) = @_;
  open IN, "< $path" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  $text =~ s:^[ \t]+$::msg;
  $text =~ s:^\n\n+:\n:msg;
  $text =~ s:^\n+\Z::msg;

  $text =~ s:(^[ \t]*\n)+(EXPORT_):$2:msg;

  open OUT, "> $path.tmp" or die;
  print OUT $text;
  close(OUT);
}

sub spaces_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- fix multiline spaces $path\n";
    spaces_txt($path);
  }
  pre_commit();
}

#####################################################################

sub concat_strings
{
  my ($path) = @_;
  open IN, "< $path" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  my $done = "";
  while ($text =~ m:"\s*?\n\s*":msp) {
    $done .= $PREMATCH;
    $text = $POSTMATCH;
  }

  open OUT, "> $path.tmp" or die;
  print OUT $done . $text;
  close(OUT);
}

sub concat_strings_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- re-concat broken strings $path\n";
    concat_strings($path);
  }
  pre_commit();
}

#####################################################################

sub align_txt
{
  my ($path) = @_;
  open IN, "< $path" or die;
  open OUT, "> $path.tmp" or die;
  my $count = 0;
  my $pushback = "";
  my $old_line = "";
  my $prev_has_backslash = 0;
  my $prev_is_decl = 0;
  while (my $line = ($pushback || <IN>)) {
    my $old_pushback = $pushback;
    $pushback = "";
    $count++;
    # skip emtpy comments
    if ($line =~ m:^\s*//\s*$:) {
      next;
    }

    # fix issues outside of strings
    my $new_line = "";
    while ($line) {
      $line =~ m{\A((?:[^"\\]|\\.)*)(.*)\Z}msg;
      my $part = $1;
      $line = $2;

      # list of issues
      $part =~ s{\s*(==?|[-+\*/&\|<>!]=|<>|>>=|<<=)(?!,) *}{ $1 }g;

      $new_line .= $part;
      last if !$line;
      $line =~ m{("(?:[^"\\]|\\.)*")(.*)}msg;
      $new_line .= $1;
      $line = $2;
    }
    $line = $new_line;

    # fix some whitespace issues
    while ($line =~ s/^((?:[^"']|'(?:[^'\\]|\\.)*'|"(?:[^\\"]|\\.)*")+?),(\S)/$1, $2/mg) {
    }
    $line =~ s:\(([A-Za-z_0-9]+)\*:($1 \*:mg;
    $line =~ s:([^\w]if|while|for)\(:$1 (:mg;
    $line =~ s:([a-zA-Z_0-9])\s*([-+*/%|&^=<>!]?=)\s*([a-zA-Z_0-9]):$1 $2 $3:mg;
    $line =~ s/^[ \t]*((?!default)[A-Za-z_0-9]+): *(;?)$/$1:$2/mg;

    # fix SPACING
    my $this_is_decl = ($line =~ m/^\s*?((static|const|unsigned|void|int|long|char|bool|struct|va_list|[a-z]+_t)\s+.*?|LIST_HEAD\s*\(.*?\));\s*?$/);
    if ($prev_is_decl && !$this_is_decl &&
	$line !~ m/^\s*$/ &&
	$line !~ m/^(\}|EXPORT_)/) {
      print OUT "\n";
    }
    $prev_is_decl = $this_is_decl;

    # break long lines
    $line = expand($line);
    my $len = length($line);
    if ($len > $max_line_length ||
	($old_pushback && $old_line =~ m/,$/)) {
      # move out any comments
      if ($line =~ m:\s*//\s:p) {
	$line = "// $POSTMATCH";
	$pushback = "$PREMATCH\n";
      } elsif ($line =~ m:\s*/\*(.*?)\*/\s*$:p) {
	$line = "/*$2*/";
	$pushback = "$PREMATCH\n";
	# break #define
      } elsif ($line =~ m/^#define\s+([A-Za-z0-9_]+(?:\s*?\(.*?\))*)\s*/p) {
	$line = "#define $1 \\\n";
	$pushback = $POSTMATCH;
	# break all else at the first possible comma, but not within strings
      } elsif ($line =~ m/^((?:[^"]|\"(?:[^"\\]|\\.)*?\")*?), *(?!\n)/mp) {
	$line = $1 . ",\n";
	$pushback = $POSTMATCH;
      }
      if ($pushback) {
	$line =~ m/^( *)/;
	my $indent = length($1);
	$indent += 8 if ($line =~ m/,$/ && !$old_pushback);
	$pushback = " " x $indent . $pushback;
	$line =~ s/\n/\\\n/mg if $prev_has_backslash;
      }
    }

    $line =~ s{ +$}{};
    $line =~ s{\s+\\$}{\\};
    $line =~ s{^#define\s+([_A-Z0-9]+)\s+(.*?\s*[^\\])$}{"\#define $1" . " " x (32 - length($1)) . "$2"}e;
    $line =~ s{^(.{0,72})\\$}{"$1" . " " x (72 - length($1)) . "\\"}e;

    $line = unexpand($line);
    $line =~ s: +\t:\t\t:g;
    print OUT $line;
    $old_line = $line;
    $prev_has_backslash = ($line =~ m/\\$/);
  }
  close(IN);
  close(OUT);
}

sub align_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- align $path\n";
    align_txt($path);
  }
  pre_commit();
}

#####################################################################

sub fix_comments
{
  my ($path) = @_;
  open IN, "< $path" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  my $done = "";
  while ($text =~ m://(.*?)//\s*?\n:p) {
    my $comment = $1;
    $done .= $PREMATCH;
    $text = $POSTMATCH;
    $comment =~ s:/:\*:g;
    $done .= "/*" . $comment . "*/\n";
  }

  $text = $done . $text;
  $done = "";
  while ($text =~ m:(/\*.*?\*/)|//([^/#].*?)\s*?\n:msp) {
    $done .= $PREMATCH;
    $text = $POSTMATCH;
    if (defined($1)) {
      print "1 '$1'\n";
      $done .= $1;
    } else {
      print "2 '$2'\n";
      $done .= "/* $2 */\n";
    }
  }

  open OUT, "> $path.tmp" or die;
  print OUT $done . $text;
  close(OUT);
}

sub fix_comments_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- fix comments $path\n";
    fix_comments($path);
  }
  pre_commit();
}

#####################################################################

my %dead_calls =
  (
   "BRICK_DEBUGGING" => "BRICK_DBG",
   "MARS_DEBUGGING" => "MARS_DBG",
   "IO_DEBUGGING" => "MARS_IO",
  );

sub remove_dead_ifdefs
{
  my $path = shift;
  my %deads = @_; # often this is empty

  open IN, "< $path" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  # remove '//#define' iff there is no blank between '//' and '#'
  my $done = "";
  while ($text =~ m:^//(\s*)\#\s*define\s*?([A-Z_0-9]+)(.*?)\n:msp) {
    my $skip = $1;
    my $dead = $2;
    my $subst = $3;
    $done .= $PREMATCH;
    $text = $POSTMATCH;
    if (length($skip) > 0) {
      print "  RETAIN DEAD '$MATCH'\n";
      $done .= $MATCH;
      next;
    }
    print "  remove dead '$dead' => '$subst'\n";
    $subst =~ s:\s*/(/.*$|\*.*?\*/\s*)::g;
    if (!$subst) {
      print "    actually removing '$dead'\n";
      $deads{$dead}++;
    }
  }

  # remove '#define' iff marked by a comment "// NO_UPSTREAM"
  $text = $done . $text;
  $done = "";
  while ($text =~ m:^\#\s*define\s*?([A-Z_0-9]+)[ \t]*/[/*][ \t]NO_UPSTREAM.*?\n:msp) {
    my $dead = "!$1";
    $done .= $PREMATCH;
    $text = $POSTMATCH;
    print "  remove NO_UPSTREAM '$dead'\n";
    $deads{$dead}++;
  }

  # remove all instances of all dead defines
  foreach my $dead (keys %deads) {
    $text = $done . $text;
    $done = "";
    my $invert_this = ($dead =~ s/^!//);
    # FIXME: nesting NYI (probably not necessary for our simple scenario)
    while ($text =~ m=^\#\s*if(n)?def\s+$dead.*?\n(.*?)(?:^\#\s*?else.*?\n(.*?))?^\#\s*?endif.*?\n=msp) {
      my $neg = ($1 || "");
      my $body_then = $2;
      my $body_else = ($3 || "");
      print "  FOUND $neg '$body_then' '$body_else'\n";
      $done .= $PREMATCH;
      $text = $POSTMATCH;
      $neg = !$neg if $invert_this;
      if ($neg) {
	$done .= $body_then;
      } else {
	$done .= $body_else;
      }
    }
    if (my $macro_call = $dead_calls{$dead}) {
      print "  remove macro call '$macro_call'\n";
      $text = $done . $text;
      $done = "";
      while ($text =~ m=^\s*$macro_call\s*?\([^)]*?\)\s*?;\n=msp) {
	print "    removing '$MATCH'\n";
	$done .= $PREMATCH;
	$text = $POSTMATCH;
      }
    }
  }

  open OUT, "> $path.tmp" or die;
  print OUT $done . $text;
  close(OUT);
}

sub remove_dead_ifdefs_all
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- remove dead ifdefs $path\n";
    remove_dead_ifdefs($path, @_);
  }
  pre_commit();
}

#####################################################################

sub dir_diff
{
  my ($oldname, $newname) = @_;
  chomp(my $oldbase = `dirname $oldname`);
  chomp(my $newbase = `dirname $newname`);
  chomp($oldname = `basename $oldname`);
  chomp($newname = `basename $newname`);
  print "oldbase='$oldbase' oldname='$oldname'\n";
  print "newbase='$newbase' newname='$newname'\n";
  $oldbase =~ s/\.(\/|$)//;
  $newbase =~ s/\.(\/|$)//;
  $oldbase =~ s:^${kernel_src}/::;
  $newbase =~ s:^${kernel_src}/::;
  print "oldbase='$oldbase' oldname='$oldname'\n";
  print "newbase='$newbase' newname='$newname'\n";
  my $down = 0;
  my $res = "";
  for (;;) {
    if ($newbase eq "") {
      while ($oldbase =~ s/^([.a-z_]+)(\/|$)//) {
	$down++;
      }
      last;
    }
    if ($oldbase eq "") {
      $res .= "$newbase/";
      last;
    }
    my $oldpre;
    if ($oldbase =~ s/^([.a-z_]+)(\/|$)//) {
      $oldpre = $1;
      next if ($oldpre eq ".");
    } else {
      die "oldbase rest: '$oldbase'";
    }
    my $newpre;
    if ($newbase =~ s/^([.a-z_]+)(\/|$)//) {
      $newpre = $1;
      next if ($newpre eq ".");
    } else {
      die "newbase rest: '$newbase'";
    }
    if ($oldpre ne $newpre) {
      $down++;
      $res .= "$newpre/";
    }
  }
  $res = "../" x $down . $res;
  if ($res) {
    return "$res$newname";
  }
  return $newname;
}

sub subst_include
{
  my ($file, $oldname, $newdir, $newname) = @_;

  open(IN, "< $mars_src/$file") or die;
  open(OUT, "> $mars_src/$file.tmp") or die;
  while (my $line = <IN>) {
    if ($line =~ m/^#include "([-a-z_.\/]*)$oldname"/) {
      my $diff = dir_diff($file, "$newdir/$newname");
      print "[$file,$newdir/$newname] \t$line";
      $line = "#include \"$diff\"\n";
      print "\t$line"
    }
    print OUT $line;
  }
  close(IN);
  close(OUT);
}

sub subst_makefile
{
  my ($oldname, $newname) = @_;
  my $oldobj = `basename $oldname`;
  chomp $oldobj;
  $oldobj =~ s/\.c/.o/;
  my $newobj = $newname;
  chomp $newobj;
  $newobj =~ s/\.c/.o/;
  my $sed = "sed 's:[.\/a-z_]*$oldobj:$newobj:'";
  print "\t$sed\n";
  system("$sed < $mars_src/Kbuild > $mars_src/Kbuild.tmp") and die;
}

sub move_file
{
  my ($oldpath, $newpath) = @_;
  my $oldbase = `basename $oldpath`;
  my $olddir = `dirname \$(find . -name $oldbase)`;
  my $newbase = `basename $newpath`;
  my $newdir = `dirname $newpath`;
  chomp ($olddir, $oldbase, $newdir, $newbase);

  print "--- move $oldpath -> $newpath\n";

  if ($oldpath =~ m/\.h$/) {
    foreach my $file (`(cd $mars_src && find . -name "*.[ch]")`) {
      chop $file;
      subst_include($file, $oldbase, $newdir, $newbase);
    }
  }

  if ($oldpath =~ m/\.c$/) {
    subst_makefile($oldpath, $newpath);
  }

  if ($oldpath =~ m/\.h$/) {
    my $oldid = uc($oldbase);
    $oldid =~ s/\./_/;
    my $newid = uc($newbase);
    $newid =~ s/\./_/;
    filter_file("$mars_src/$oldpath", "^#[a-z]+\\s*", $oldid, "", $newid);
  }

  pre_commit();

  if ($oldpath ne $newpath) {
    system "git mv $mars_src/$oldpath $mars_src/$newpath" and die;
  }
}

#####################################################################

sub filter_file
{
  my ($path, $pre, $left, $post, $right) = @_;
  local $/;
  open IN, "< $path" or die "path '$path'";
  my $text = <IN>;
  close(IN);
  $text =~ s:($pre)($left)($post):$1$right$3:mg;
  open OUT, "> $path.tmp" or die;
  print OUT $text;
  close(OUT);
}

sub filter_dir
{
  my ($dir, $pre, $left, $post, $right,$except) = @_;
  print "--- filter directory $dir '$left' -> '$right'\n";
  foreach my $path (`ls $mars_src/$dir/*.[ch]`) {
    chomp $path;
    next if defined($except) && $path =~ m/$except/;
    #print "$path\n";
    filter_file($path, $pre, $left, $post, $right);
  }
  pre_commit();
}

sub filter_all
{
  my ($pre, $left, $post, $right,$except) = @_;
  print "--- filter '$left' -> '$right'\n";
  foreach my $path (`find $mars_src/ -name "*.[ch]"`) {
    chomp $path;
    next if defined($except) && $path =~ m/$except/;
    #print "$path\n";
    filter_file($path, $pre, $left, $post, $right);
  }
  pre_commit();
}

#####################################################################

sub remove_macro
{
  my ($path, $name) = @_;
  open IN, "< $path" or die;
  local $/;
  my $text = <IN>;
  close(IN);

  $text =~ s:^\#define $name.*?(\\\n.*?)*\n\n?::msg;
  $text =~ s:^\s*$name\s*\([^()]*\);\s*?\\?\n::msg;
  $text =~ s:$name\s*\(([^()]*)\):$1:msg;

  open OUT, "> $path.tmp" or die;
  print OUT $text;
  close(OUT);
}

sub remove_macro_all
{
  my ($name) = @_;
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    print "--- fix remove macro $name $path\n";
    remove_macro($path, $name);
  }
  pre_commit();
}

#####################################################################

sub rename_newlink
{
  filter_all("[^a-z]", "new_stat", "[^a-z]", "stat_val");
  filter_all("[^a-z]", "new_link", "[^a-z]", "link_val");
  commit("all: rename new_{stat,link}");
}

sub rename_mref
{
  filter_all("[^a-z]", "ref_count", "[^a-z]", "obj_count");
  filter_all("[^a-z]", "ref_initialized", "[^a-z]", "obj_initialized");
  filter_all("[^a-z]", "_mref_check", "[^a-z]", "obj_check");
  filter_all("[^a-z]", "_mref_get", "", "obj_get");
  filter_all("[^a-z]", "_mref_put", "", "obj_put");
  filter_all("[^a-z]", "_mref_free", "", "obj_free");


  filter_all("", "FIELD_REF", "", "FIELD_XAWAY");
  filter_all("", "_REF", "", "_AIO");
  filter_all("", "MREF", "", "AIO");
  filter_all("[^A-Z]", "REF", "[^A-Z]", "AIO");
  filter_all("[^a-z]", "mrefs", "[^a-z]", "aios");
  filter_all("[^a-z]", "mref", "[^a-z]", "aio");
  filter_all("[^a-z]", "mref", "[^a-z]", "aio");
  filter_all("[^a-z]", "ref_", "", "io_");
  filter_all("", "sub_ref", "", "sub_aio");
  filter_all("", "shadow_ref", "", "shadow_aio");
  filter_all("", "ref len", "", "aio len");
  filter_all("", " ref ", "", " aio ");
  filter_all("", "log_refs", "", "log_aios");
  filter_all("", "XAWAY", "", "REF");
  commit("all: rename mref_object to aio_object");
}

sub rename_to_xio
{
  system "rm -rf $mars_src/xio_bricks/ $mars_src/mars_light";
  system "git clean -f" and die;
  system "mkdir -p $mars_src/lib $mars_src/xio_bricks/unused $mars_src/mars_light";

  filter_all("", "DO_INIT\\(mars", "", "DO_INIT(xio");
  filter_all("[^a-z]", "init_mars", "[^a-z]", "init_xio");
  filter_all("[^a-z]", "exit_mars", "[^a-z]", "exit_xio");

  #commit("all: x1");

  move_file("mars_generic.c", "xio_bricks/xio.c");

  my %rename_c =
    (
     "sy_old/mars_proc.c" => "mars_light/mars_proc.c",
     "sy_old/mars_light.c" => "mars_light/mars_light.c",
     "sy_old/sy_generic.c" => "mars_light/light_strategy.c",
     "sy_old/sy_net.c" => "mars_light/light_net.c",
     "mars_server_strategy.c" => "mars_light/light_server_strategy.c",
    );
  foreach my $src (keys %rename_c) {
    my $dst = $rename_c{$src};
    move_file($src, $dst);
  }

  #commit("all: x2");

  my @brick_list =
    (
     "aio_user",
     "bio",
     "sio",
     "buf",
     "usebuf",
     "check",
     "client",
     "server",
     "copy",
     "dummy",
     "if",
     "trans_logger",
     "net",
    );
  foreach my $suff (@brick_list) {
    my $src = $suff;
    $src =~ s/_user//;
    my $sub = ($suff =~ m/aio_user|buf|check|dummy/) ? "/unused" : "";
    move_file("mars_$src.c", "xio_bricks$sub/xio_$suff.c");
  }

  #commit("all: x3");

  foreach my $suff (@brick_list) {
    my $src = $suff;
    $src =~ s/_user//;
    my $sub = ($suff =~ m/aio_user|buf|check|dummy/) ? "/unused" : "";
    move_file("mars_$src.h", "xio_bricks$sub/xio_$suff.h");
  }
  foreach my $suff (@brick_list) {
    my $src = $suff;
    $src =~ s/_user//;
    filter_all("", "mars_$src", "(?:[^.]|\$)", "xio_$suff");
  }

  my @lib_list =
    (
     "lib_pairing_heap",
     "lib_queue",
     "lib_rank",
     "lib_timing",
     "lib_limiter",
    );
  foreach my $suff (@lib_list) {
    move_file("$suff.c", "lib/$suff.c") if -e "$mars_src/$suff.c";
  }

  # these are referencing xio.h
  my @lib_list_xio =
    (
     "lib_mapfree",
     "lib_log",
    );
  foreach my $suff (@lib_list_xio) {
    move_file("$suff.c", "xio_bricks/$suff.c") if -e "$mars_src/$suff.c";
  }

  foreach my $suff (@lib_list_xio) {
    move_file("$suff.h", "xio_bricks/$suff.h");
  }

  my %rename_h = (
		  "sy_old/mars_proc.h" => "mars_light/mars_proc.h",
		  "sy_old/strategy.h" => "mars_light/light_strategy.h",
		  "mars.h" => "xio_bricks/xio.h",
		 );
  foreach my $src (keys %rename_h) {
    my $dst = $rename_h{$src};
    move_file($src, $dst);
  }

  foreach my $suff (@lib_list) {
    move_file("$suff.h", "lib/$suff.h");
  }

  filter_all("", "MARS_LIB_LIMITER", "", "LIB_LIMITER");
  filter_all("", "MARS_LIB_TIMING", "", "LIB_TIMING");
  filter_all("", "MARS_LIB_MAPFREE", "", "XIO_LIB_MAPFREE");
  filter_all("", "MARS_CHECKSUM", "", "XIO_CHECKSUM");
  filter_all("", "MARS_LOG_", "", "XIO_LOG_");

  #commit("all: x4");

  move_file("compat.h", "vfs_compat.h");

  my @away = (
	     );
  foreach my $suff (@away) {
    filter_all("", "mars_$suff", "", "XAWAY_$suff");
  }

  my @ids = (
	     "info",
	     "socket",
	     "limiter",
	     "create_",
	     "send_",
	     "recv_",
	     "desc_",
	     "tcp_",
	     "cmd",
	     "translate_",
	     "accept_",
	     "get_socket",
	     "put_socket",
	     "shutdown_socket",
	     "port",
	     "digest",
	     "get_info",
	     "throttle",
	     "brick",
	     "input",
	     "output",
	     "alloc_",
	     "free_",
	     "limit",
	     "timespec",
	     "tfm",
	     "sender",
	     "receiver",
	     "handler",
	     "cb",
	     "logger",
	     "merge",
	     "congested",
	     "max_",
	     "make",
	     "kill",
	     "global_ban",
	     "global_io",
	     "mapfree",
	     "proto_",
	     "\{send",
	    );
  foreach my $suff (@ids) {
    filter_all("", "mars_$suff", "", "xio_$suff");
  }
  filter_all("", " of mars ", "", " of xio ");
  filter_all("", "mars_power_led", "", "xio_set_power_led");
  filter_all("", "led_on", "", "on_led");
  filter_all("", "led_off", "", "off_led");
  filter_all("", "mars_trigger", "", "local_trigger");
  filter_all("", "mars_remote_trigger", "", "remote_trigger");

  #commit("all: x5");

  my @bigids = (
		"PRIO", "MAX_SEGMENT_SIZE", "MAX_AIO",
		"BRICK", "INPUT", "OUTPUT", "TYPES", "MAKE",
		"MSG", "DBG", "INF", "WRN", "ERR", "FAT", "IO", "RPL", "STAT",
		"DEBUGGING",
		"BUF", "DESC_MAGIC",
	       );
  foreach my $suff (@bigids) {
    filter_all("", "MARS_$suff", "[^A-Z]", "XIO_$suff");
  }
  filter_all("", "MARS-specific", "", "XIO-specific");
  filter_all("\\\"", "MARS", "\\\"", "XIO");
  filter_all("", "MARS is ", "", "XIO is ");
  filter_all("", "in MARS", "", "in XIO");
  filter_all("", "MARS flags", "", "XIO flags");
  filter_all("", "DESCRIPTION.\"MARS", "", "DESCRIPTION\(\"XIO", "mars");

  #commit("all: x6");

  filter_all("", "FORMAT_VERSION", "LOG_FORMAT_VERSION", "");


  #, "brick", "input", "output"
  filter_all("[A-Z]", "\\(mars", "[^_]", "(xio");

  filter_all("", "_mars_##", "", "_xio_##");

  filter_file("$mars_src/brick.h", "", "BRITYPE", "", "BRICKTYPE");

  filter_all("", "NR_SOCKETS", "", "NR_SERVER_SOCKETS");

  # revert some wrong XIO

  #commit("all: x7");
  filter_all("", "xio_limit", "", "rate_limit");
  filter_dir("lib", "", "XIO_ERR[(]", "", "printk\(KERN_ERR ");
  filter_dir(".", "", "XIO", "", "BRICK");
  filter_dir(".", "", "aio", "", "object");
  #commit("all: x8");

  # revert XAWAY
  filter_all("", "XAWAY", "", "mars");

  align_all();

  system "git rm -rf $mars_src/sy_old/" and die;

  commit("all: rename mars_* bricks to xio_* bricks");
}

sub rename_members
{
  my %rename = (
		"get_nr" => "get_brick_nr",
		"put_nr" => "put_brick_nr",
		#"" => "",
	       );
  foreach my $src (sort keys %rename) {
    my $dst = $rename{$src};
    filter_all("[^a-z]", $src, "[^a-z]", $dst);
    commit("infra: rename $src to $dst");
  }
}

###################################################################

sub find_branches
{
  my ($base_branch, $branches) = @_;
  $branches = `git branch --list` unless defined($branches);
  $branches =~ s/\*//msg;
  my %result;
  foreach my $branch (split(/ /,$branches)) {
    chomp $branch;
    next unless $branch;
    next if $branch =~ m/tmp/;
    next if $branch =~ m/ptr/;
    next if $branch eq $base_branch;
    my $cmd = "git rev-list --reverse --ancestry-path $branch ^$base_branch";
    #print "$cmd\n";
    my $list = `$cmd`;
    $list =~ s:\n: :msg;
    next unless $list;
    print "branch: $branch\n";
    $result{$branch} = $list;
  }
  return %result;
}

sub rebase_patch
{
  my ($commit, $to, $via) = @_;
  system("git checkout $commit") and die;
  system("git log -1 $commit --format='format:%B' > /tmp/msg");
  my $author = `git log -1 $commit --format="format:%aN <%aE>"`;
  chomp $author;
  my $date = `git log -1 $commit --format="format:%aD"`;
  chomp $date;
  system("git branch -D ptr > /dev/null 2>&1");
  system("git checkout -b ptr") and die;
  $delta_mode = 1;
  &$via();
  $delta_mode = 0;
  system("git commit -a --author='$author' --date='$date' -F /tmp/msg") and die;
  system("git diff --patch-with-stat $to..ptr > /tmp/patch.diff") and die;
  system("git checkout $to") and die;
  if (-s "/tmp/patch.diff") {
    system("git apply --index /tmp/patch.diff") and die;
    system("git commit --author='$author' --date='$date' -F /tmp/msg") and die;
  } else {
    print "skipping rebase of '$commit'\n";
  }
}

sub rebase_patchset
{
  my ($list, $from, $to, $via) = @_;

  system("git checkout $to") and die;
  system("git branch -D NEW-$from > /dev/null 2>&1");
  system("git checkout -b NEW-$from") and die;
  foreach my $commit (split(/ /, $list)) {
    chomp $commit;
    print "REBASE COMMIT '$commit'\n";
    rebase_patch($commit, "NEW-$from", $via);
  }
  system("git branch -D ptr");
}

###################################################################

sub checkout_base
{
  system("find $mars_src \\( -name '*.tmp' -o -name '*.o' -o -name '*~' -o -name '*.mod.c' \\) -exec rm {} \\;") and die;

  system "git checkout $mars_master_branch" and die;
  system "git add rework-mars-for-upstream.pl";
  system "git commit -m 'aaa'";
  system "git branch -D $mars_slave_branch";
  system "git checkout -b $mars_slave_branch" and die;
}

sub prepare_mars
{
  remove_macro_all("SAFE_STR");
  commit("all: remove macro SAFE_STR()");

  remove_macro_all("EXPORT_SYMBOL_GPL");
  remove_macro_all("EXPORT_SYMBOL");
  commit("all: remove EXPORT_SYMPOL()");

  includes_all();
  commit("all: rename kernel includes");

  statics_all();
  commit("all: remove static = 0 initializations");

  returns_all();
  commit("all: replace return statements in void functions");

  macros_all();
  commit("all: fix simple defines");

  attribute_all();
  commit("all: rename __attribute__ calls");

  spaces_all();
  commit("all: fix multiline spacing");

  align_all();
  commit("all: adjust tabs and spaces");

  braces_all();
  commit("all: fix braces");

  fix_comments_all();
  commit("all: fix C99 comments");

  rename_newlink();
  rename_mref();
  rename_members();
  rename_to_xio();

  system "wc -l $mars_src/*.[ch] $mars_src/*/*.[ch] | sort -n";
}

###################################################################

sub remove_compat
{
  my @del = ("mars_net_compat.c");
  foreach my $rest (@del) {
    system "git rm $mars_src/$rest" and die;
  }
}

sub remove_fsf
{
  foreach my $path (`find $mars_src -name "*.[ch]"`) {
    chomp $path;
    open IN, "< $path" or die;
    local $/;
    my $text = <IN>;
    close(IN);

    $text =~ s:^ \*\n \* This file is part of .*?\n::msp;
    $text =~ s:^ \*\n \* You should have received.*? \*/: \*/:msp;

    open OUT, "> $path.tmp" or die;
    print OUT $text;
    close(OUT);
  }
  pre_commit();
}

sub prepare_nonportable
{
  system("find $mars_src \\( -name '*.tmp' -o -name '*.o' -o -name '*~' -o -name '*.mod.c' \\) -exec rm {} \\;") and die;

  system "git checkout $mars_slave_branch" and die;
  system "git branch -D $mars_nonport_branch";
  system "git checkout -b $mars_nonport_branch" and die;

  remove_fsf();
  commit("all: remove FSF address from copyright");

  system "git rm $mars_src/Makefile" and die;
  commit("infra: remove userspace Makefile");

  system "git mv $mars_src/Kbuild $mars_src/Makefile" and die;
  commit("infra: move $mars_src Kbuild to Makefile");

  rework_all();
  commit("all: strip and move code");

  remove_dead_ifdefs_all();
  commit("all: remove dead #ifdefs");

  remove_dead_ifdefs_all("!MARS_KERNEL_UPSTREAM");
  commit("all: remove !MARS_KERNEL_UPSTREAM", 2);

  remove_compat();
  commit("all: remove obsolete compatibility code");

  spaces_all();
  commit("all: fix multiline spacing", 2);

  concat_strings_all();
  commit("all: re-concat broken string constants");

  align_all();
  commit("all: adjust tabs and spaces", 2);

  braces_all();
  commit("all: fix braces", 2);

  fix_comments_all();
  commit("all: fix C99 comments", 2);

  system "wc -l $mars_src/*.[ch] $mars_src/*/*.[ch] | sort -n";
}

###################################################################

my %kernel_moves;
tie %kernel_moves, 'Tie::IxHash',
  (
   # core brick framework
   "lamport.h" => "$kernel_incl_brick/lamport.h",
   "lamport.c" => "$kernel_src_brick/lamport.c",
   "brick_say.h" => "$kernel_incl_brick/brick_say.h",
   "brick_say.c" => "$kernel_src_brick/brick_say.c",
   "brick_mem.h" => "$kernel_incl_brick/brick_mem.h",
   "brick_mem.c" => "$kernel_src_brick/brick_mem.c",
   "brick_checking.h" => "$kernel_incl_brick/brick_checking.h",
   "meta.h" => "$kernel_incl_brick/meta.h",
   "brick.h" => "$kernel_incl_brick/brick.h",
   "brick.c" => "$kernel_src_brick/brick.c",

   # additional framework parts (this could go to separate dirs if somebody wants it)
   "lib/lib_pairing_heap.h" => "$kernel_incl_lib/lib_pairing_heap.h",
   "lib/lib_queue.h" => "$kernel_incl_brick/lib_queue.h",
   "lib/lib_rank.h" => "$kernel_incl_lib/lib_rank.h",
   "lib/lib_rank.c" => "$kernel_src_lib/lib_rank.c",
   "lib/lib_limiter.h" => "$kernel_incl_lib/lib_limiter.h",
   "lib/lib_limiter.c" => "$kernel_src_lib/lib_limiter.c",
   "lib/lib_timing.h" => "$kernel_incl_lib/lib_timing.h",
   "lib/lib_timing.c" => "$kernel_src_lib/lib_timing.c",
   "vfs_compat.h" => "$kernel_incl_lib/vfs_compat.h",

   # xio framework (this could go to separate dirs if somebody wants it)
   "xio_bricks/xio.h" => "$kernel_incl_xio/xio.h",
   "xio_bricks/xio.c" => "$kernel_src_xio/xio.c",
   "xio_bricks/xio_net.h" => "$kernel_incl_xio/xio_net.h",
   "xio_bricks/xio_net.c" => "$kernel_src_xio/xio_net.c",

   "xio_bricks/lib_mapfree.h" => "$kernel_incl_xio/lib_mapfree.h",
   "xio_bricks/lib_mapfree.c" => "$kernel_src_xio/lib_mapfree.c",
   "xio_bricks/lib_log.h" => "$kernel_incl_xio/lib_log.h",
   "xio_bricks/lib_log.c" => "$kernel_src_xio/lib_log.c",

   # xio personality bricks
   "xio_bricks/xio_bio.h" => "$kernel_incl_xio/xio_bio.h",
   "xio_bricks/xio_bio.c" => "$kernel_src_xio/xio_bio.c",
   "xio_bricks/xio_sio.h" => "$kernel_incl_xio/xio_sio.h",
   "xio_bricks/xio_sio.c" => "$kernel_src_xio/xio_sio.c",
   "xio_bricks/xio_client.h" => "$kernel_incl_xio/xio_client.h",
   "xio_bricks/xio_client.c" => "$kernel_src_xio/xio_client.c",
   "xio_bricks/xio_if.h" => "$kernel_incl_xio/xio_if.h",
   "xio_bricks/xio_if.c" => "$kernel_src_xio/xio_if.c",
   "xio_bricks/xio_copy.h" => "$kernel_incl_xio/xio_copy.h",
   "xio_bricks/xio_copy.c" => "$kernel_src_xio/xio_copy.c",
   "xio_bricks/xio_trans_logger.h" => "$kernel_incl_xio/xio_trans_logger.h",
   "xio_bricks/xio_trans_logger.c" => "$kernel_src_xio/xio_trans_logger.c",
   "xio_bricks/xio_server.h" => "$kernel_incl_xio/xio_server.h",
   "xio_bricks/xio_server.c" => "$kernel_src_xio/xio_server.c",

   # Mars Light application strategy (IMHO separation from Light application makes no sense)
   "mars_light/light_strategy.h" => "$kernel_incl_light/light_strategy.h",
   "mars_light/light_strategy.c" => "$kernel_src_light/light_strategy.c",
   "mars_light/light_net.c" => "$kernel_src_light/light_net.c",

   # rest of xio brick depedency
   "mars_light/light_server_strategy.c" => "$kernel_src_light/light_server_strategy.c",

   # Mars Light application
   "mars_light/mars_proc.h" => "$kernel_incl_light/mars_proc.h",
   "mars_light/mars_proc.c" => "$kernel_src_light/mars_proc.c",
   "mars_light/mars_light.c" => "$kernel_src_light/mars_light.c",

   # Build environment
   "Makefile" => "$kernel_src/Makefile",
   "Kconfig" => "$kernel_src/Kconfig",
  );

my %exceptions =
  (
   # checkpatch.pl exceptions: IMHO some are false positives.
   "brick_mem"         => ",MACRO_WITH_FLOW_CONTROL",
   "brick_checking"    => ",MACRO_WITH_FLOW_CONTROL",
   "brick"             => ",TRAILING_SEMICOLON",
   "lib_pairing_heap"  => ",TRAILING_SEMICOLON",
   "lib_queue"         => ",TRAILING_SEMICOLON",
   "vfs_compat"        => ",TRAILING_SEMICOLON",
   "xio"               => ",TRAILING_SEMICOLON",
   "xio_net"           => ",SUSPECT_CODE_INDENT,MACRO_WITH_FLOW_CONTROL",
   "lib_log"           => ",COMPLEX_MACRO",
   "xio_trans_logger"  => ",STORAGE_CLASS",
   "mars_proc"         => ",COMPLEX_MACRO",
   "light_strategy"    => ",TRAILING_SEMICOLON",
  );

sub prepare_kernel
{
  my $mars_dir = `pwd`;
  chomp $mars_dir;
  $mars_dir .= "/$mars_src";

  my $patches_1 = scalar(keys(%kernel_moves));

  print "\n";
  print "======================================================\n";
  print "transferring $mars_dir to $kernel_dir\n";
  chdir($kernel_dir) or die "cannot chdir to '$kernel_dir'";
  my @trail_list = reverse(`git log --oneline $kernel_master_branch..$kernel_trail_branch | cut -d" " -f1`);
  my $patches_2 = scalar(@trail_list);
  my $patches_total = $patches_1 + $patches_2;
  print "#patches: $patches_1 + $patches_2 = $patches_total\n";
  print "======================================================\n";

  system "git checkout $kernel_master_branch" and die;


  system "git branch -D $kernel_slave_branch";
  system "git checkout -b $kernel_slave_branch" and die;
  system "mkdir -p $kernel_incl_lib $kernel_incl_brick $kernel_incl_xio $kernel_incl_light";
  system "mkdir -p $kernel_src_lib $kernel_src_brick $kernel_src_xio $kernel_src_light";

  my %commits;
  tie %commits, 'Tie::IxHash';

  my $nr = 0;
  foreach my $src (keys(%kernel_moves)) {
    $nr++;
    my $dst = $kernel_moves{$src};
    my $commit = `basename $dst`;
    chomp $commit;
    $commit =~ s/\..*//;
    if (defined($commits{$commit})) {
      $commits{$commit} = "$dst " . $commits{$commit};
    } else {
      $commits{$commit} = "$dst";
    }
    print "--- $commit moving $src => $dst\n";
    open(IN, "< $mars_dir/$src") or die;
    open(OUT, "> $dst") or die;
    while (my $line = <IN>) {
      if ($line =~ m/^\#include "([-a-z_.\/]*)"/) {
	my $oldname = $1;
	my $oldpath = `basename $oldname`;
	chomp $oldpath;
	my $newpath = $kernel_moves{$oldpath};
	$newpath = $kernel_moves{"lib/$oldpath"} unless defined($newpath);
	$newpath = $kernel_moves{"xio_bricks/$oldpath"} unless defined($newpath);
	$newpath = $kernel_moves{"mars_light/$oldpath"} unless defined($newpath);
	die "missing definition for '$oldpath'" unless defined($newpath);
	if ($newpath =~ m:^include/(.*):) {
	  $line = "#include <$1>\n";
	} else {
	  my $diff = dir_diff($oldname, $newpath);
	  $line = "#include \"$diff\"\n";
	}
	print "  $oldpath -> $line";
      }
      print OUT $line;
    }
    close(IN);
    close(OUT);
  }

  foreach my $commit (keys(%commits)) {
    my $dst = $commits{$commit};
    system "git add $dst" and die "add '$dst'\n";

    my $patch = "/tmp/$commit.diff";
    system "git diff --cached > $patch" and die;
    my $exeption = ($exceptions{$commit} || "");
    print "checkpatch $patch\n";
    system "$checkpatch --no-signoff --max-line-length=$max_line_length --show-types --ignore=$checkpatch_ignore$exeption $patch";

    my $msg = "mars: add new module $commit";
    system "git commit -s -m '$msg'" and die "commit '$msg'\n";
  }
  foreach my $trail (@trail_list) {
    print "$trail\n";
    system "git cherry-pick $trail";
  }
  system "rm -f 00*.patch";
  system "git format-patch $kernel_master_branch..$kernel_slave_branch";
}

##### main program

checkout_base();

prepare_mars();

my %branches = find_branches($mars_master_branch);
foreach my $sub_branch (keys(%branches)) {
  next if $sub_branch eq $mars_slave_branch;
  next if $sub_branch eq $mars_nonport_branch;
  next if $sub_branch =~ m/^NEW-/;
  rebase_patchset($branches{$sub_branch}, $sub_branch, $mars_slave_branch, \&prepare_mars);
}

prepare_nonportable();

prepare_kernel();
