#!/usr/bin/env bash
# gpg-sign-keys.sh - (semi)automatic GnuPG keysigning for busy people
# http://www.roe.ch/GPG
#
# Copyright (C) 2003-2008, Daniel Roethlisberger <daniel@roe.ch>
# All rights reserved.
#
# Redistribution and use, with or without modification, are permitted
# provided that the following conditions are met:
# 1. Redistributions must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
# 2. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Many thanks to the following contributors of patches and good ideas:
# - Tobias Sager <tsager@gmx.ch>
# - Daniel Hottinger <hotti@hotti.ch>
# - Tobias Klauser <tklauser@nuerscht.ch>
#
# $Id: gpg-sign-keys.sh 25 2008-12-14 20:07:10Z roe $
REVISION='$Id: gpg-sign-keys.sh 25 2008-12-14 20:07:10Z roe $'


##############################################################################
# requirements

# GnuPG for the actual signing, of course   - http://www.gnupg.org/
# mktemp for secure temp file handling      - http://www.mktemp.org/
# An MSA supporting the -s/-c/-b switches (see ``configuration'' below)


##############################################################################
# environment vars

# MYKEY:   Private key(s) to sign with, whitespace separated
# CC:      Mail addresses to carbon copy the signature notifications
# BCC:     Mail addresses to blind carbon copy the signature notifications
# OWNER:   Real name of person running this script, normally from /etc/passwd


##############################################################################
# configuration

# MSA: Your mail submission agent, called as follows:
# cat message | $MSA $MSA_OPTS -s "some subject" -b "$BCC" -c "$CC" $addresses
# Using any of mail, mailx or mutt should work fine, though you should make
# sure that mail sent this way will have a sensible/valid From: header.
MSA="mutt"
MSA_OPTS=""

# GnuPG
# You can use custom extra options to pass to GnuPG, eg. --use-agent for using
# gpg-agent, or options affecting the number of questions asked by GnuPG when
# signing keys.  Use GnuPG options with care: some more intrusive options may
# alter the behaviour of GnuPG too much and break the script.
GPG="gpg"
GPG_OPTS=""


##############################################################################
# TODO / known bugs and limitations

# Should be done:
# - Better support for making gpg ask less questions
# - Better support for "check first, then do all the signing", required for
#   doing any serious work with gpg-agent -- optionally feed list of uids and
#   fingerprints to ${PAGER:-more} and provide ways to yank out keys without
#   terminating the key signing process
# - Better support for gpg-agent (currently in CVS only, but should work with
#   the current 1.2.x stable series of GnuPG, which has support for talking
#   to gpg-agent -- this will make signing many keys even easier)
# - Don't send/mail keys when there was nothing to sign

# Might be done:
# - Add support for encrypting signatures, and only send them to
#   the email addresses of their respective uid.
# - Maybe add some generic form of support for plugging into a
#   challenge-response system.
# I don't think either of these are the Right Thing To Do, but this script
# could/should implement them anyway, if just for completeness.


##############################################################################
# check requirements

if [ "x`which $GPG`" = "x" ]; then
	echo "${SCRIPT}: Get and install GnuPG from http://www.gnupg.org/" >&2
	exit 1
fi

if [ "x`which mktemp`" = "x" ]; then
	echo "${SCRIPT}: Get and install mktemp from http://www.mktemp.org/" >&2
	exit 1
fi

if [ "x`which $MSA`" = "x" ]; then
	echo "${SCRIPT}: Cannot find your MSA $MSA - fix \$MSA in $SCRIPT" >&2
	exit 1
fi


##############################################################################
# check and parse options and environment

# script basename
SCRIPT=`basename $0`

# usage and version
version() {
	echo "$SCRIPT `echo $REVISION | awk '{ print $3 }'`" >&2
	echo "Copyright (C) 2003-2008, Daniel Roethlisberger <daniel@roe.ch>" >&2
	echo "Distributed under a BSD style license, see source for details." >&2
	echo "Check http://dragon.roe.ch/bitsnpieces/scripts/gpg/ for updates." >&2
	exit 1
}
usage() {
	cat >&2 <<EOF
Usage:	$SCRIPT [options...] [-u keyids] [-f keyring] [keyids...]
Options:
	-f file	 Get list of keyids to sign from keyring file
	-u ids	 Key(s) to sign with, multiple -u id1 -u id2 or -u 'id1 id2'
	-x ids	 eXceptions - don't process these keys (multiple like -u)
	-c addr	 CC all signed key emails to address
	-b addr	 BCC all signed key emails to address
	-a file	 Append the content of file to the email body
	-n name	 Override your name normally obtained from /etc/passwd
	-y	 Assume yes on most questions (-Y for no questions asked at all)
	-I	 Don't import the -f keyring into the default keyring first
	-S	 Don't sign any keys - just do the sending/mailing
	-K	 Don't send signed keys to your default keyserver
	-M	 Don't mail signed keys to key owners
	-E	 Don't encrypt mails with owners key
	-U	 Don't update the trustdb after processing all keys
	-v/-h	 Display version/help and exit
The script will guide you through signing all keys in the -f keyring, or just
the keys explicitly specified.  All GnuPG operations are done in your default
keyring.  You will be asked to confirm every mail being sent unless -y is used.
The -u, -c, -b, and -n options override the env vars MYKEY, CC, BCC, OWNER
respectively.  For more details, read the source.
EOF
	exit 1
}

# options
unset keyring mykey except noask noask2 noimport nosign nosend nomail noupdate
unset encrypt append

eval set -- `getopt f:u:x:c:b:a:n:yYISKMEUvh "$@"` || usage
for token; do
	case "$token" in
		-f)	shift; keyring="$1"; shift;;
		-u)	shift; mykey="$mykey $1"; MYKEY="$mykey"; shift;;
		-x)	shift; except="$except $1"; shift;;
		-c)	shift; CC="$1"; shift;;
		-b)	shift; BCC="$1"; shift;;
		-a)	shift; append="$1"; shift;;
		-n)	shift; OWNER="$1"; shift;;
		-y)	shift; noask=1;;
		-Y)	shift; noask=1; noask2=1;;
		-I)	shift; noimport=1;;
		-S)	shift; nosign=1;;
		-K)	shift; nosend=1;;
		-M)	shift; nomail=1;;
		-E)	shift; noencrypt=1;;
		-U)	shift; noupdate=1;;
		-h)	shift; usage;;
		-v)	shift; version;;
		--)	shift; break;;
	esac
done
ids="$@"

# clean some vars
MYKEY=`echo $MYKEY | sed -e 's/  */ /g' -e 's/^ *//g' -e 's/ *$//g' -e 's/0x//g' | tr [:lower:] [:upper:]`
except=`echo $except | sed -e 's/  */ /g' -e 's/^ *//g' -e 's/ *$//g' -e 's/0x//g' | tr [:lower:] [:upper:]`
ids=`echo $ids | sed -e 's/  */ /g' -e 's/^ *//g' -e 's/ *$//g' -e 's/0x//g' | tr [:lower:] [:upper:]`

# need MYKEY
if [ "x$MYKEY" = "x" ]; then
	echo 'You must either use -u or set $MYKEY to your private key id(s)!' >&2
	usage
fi

# need at least a keyid or keyring
if [ "x$ids$keyring" = "x" ]; then
	echo 'You must provide key id(s) to sign, or use -f on a keyring file!' >&2
	usage
fi


##############################################################################
# functions

# -opts enabled bold echo
shout() {
	echo -n ${CB}
	echo $@${CN}
}

# ask "Question" [y|n]
ask() {
	local ans opts
	[ "$2" = "y" ] && opts="[Y/n]" || opts="[y/N]"
	while true; do
		read -p "$1? $opts " ans
		[ -z "$ans" ] && ans=${2:-n}
		case "$ans" in
			y|Y|j|J) return 0 ;;
			n|N)  return 1 ;;
		esac
	done
}

# $1: id, $2: address
mail_key() {
	mail_id="$1"
	mail_address="$2"

	mykey_list=`echo $MYKEY | sed 's/ /, /g'`
	if [ `echo $MYKEY | wc -w` -eq 1 ]; then
		key_s='key'
	else
		key_s='keys'
	fi

	cat <<EOF >$tmp
Hi, this is the $SCRIPT script running on behalf of
$OWNER.

Below is your signed key $id.  Please do not forget to sign
my owner's $key_s $mykey_list as well.  If you have reasons
not to sign the $key_s, my owner would like to know about them.

EOF

	if [ "x$nosend" = "x" ]; then
		cat <<EOF >>$tmp
Additionally your signed key has been uploaded to the keyservers.

EOF
	else
		cat <<EOF >>$tmp
Your key has not been uploaded to any keyserver.  Please make
sure that you upload your key and its signatures manually.

EOF
	fi

	if [ -n "$append" -a -r "$append" ]; then
		cat "$append" >>$tmp
	fi

	$GPG --fingerprint $mail_id >>$tmp
	$GPG --armor --export $mail_id >>$tmp

	if [ -r ~/.signature ]; then
		cat <<EOF >>$tmp

-- 
EOF
		cat ~/.signature >>$tmp
	fi

	if [ "x$noencrypt" = "x" ]; then
		mv $tmp $tmp.orig
		$GPG --armor --encrypt --encrypt-to $mail_id --recipient $mail_id < $tmp.orig > $tmp 2>/dev/null
		rm $tmp.orig
	fi

	cat $tmp | $MSA $MSA_OPTS -s "Your key $mail_id signed by $mykey_list" $mailopts $mail_address
}

# clean up
cleanup() {
	rm -rf $tmpdir
}

# console interrupt (ctrl-c)
trap_int() {
	shout 'Chickening out, already?'
	cleanup
	exit 2
}

# terminate
trap_term() {
	shout 'Ouch!'
	cleanup
	exit 2
}


##############################################################################
# set up things

# GnuPG
GPG="$GPG --no-auto-check-trustdb $GPG_OPTS"

# colours: bold and normal
CB='[1;37m'
CN='[0;37m'

# get owner name
if [ "x$OWNER" = "x" ]; then
	owner_id=`id -un`
	OWNER=`grep "^$owner_id:" /etc/passwd | cut -f 5 -d ':' | sed 's/^\([^,]*\),.*$/\1/'`
	OWNER=${OWNER:-my owner}
fi

# set mail options
mailopts=''
if [ "x$BCC" != "x" ]; then
	MAILOPTIONS="$mailopts -b $BCC"
fi
if [ "x$CC" != "x" ]; then
	MAILOPTIONS="$mailopts -c $CC"
fi

# trap signals
trap 'trap_int' 2
trap 'trap_term' 15

# temp files
tmpdir=`mktemp -d -t gpg-sign-keys.XXXXXXXXXXXX` || exit 1
tmp="$tmpdir/mail.tmp"


##############################################################################
# process keyring, if necessary, and prune id list

# check keyring file, dearmor
if [ "x$keyring" != "x" ]; then
	keyring=`echo "$keyring" | awk '!/\// { print "./" $1 } /\// { print $1 }'`
	if [ ! -r "$keyring" ]; then
		echo "${SCRIPT}: $keyring: No such keyring." >&2
		exit 1
	fi
	keyring_ext=`echo "$keyring" | sed 's/^.*\.\([^.]*\)$/\1/'`
	if [ "x$keyring_ext" = "xasc" ]; then
		if [ "$noask" ] || \
		   ask "Automatically dearmor keyring $keyring" n; then
			shout "Dearmoring keyring $keyring to $keyring.gpg"
			$GPG --dearmor $keyring || exit 1
			keyring="$keyring.gpg"
			if [ ! -r "$keyring" ]; then
				echo "${SCRIPT}: $keyring: No such keyring.  Dearmoring failed?" >&2
				exit 1
			fi
		else
			echo "${SCRIPT}: $keyring: Keyring is ASCII armored.  Dearmor it manually." >&2
			exit 1
		fi
		unset ans
	fi
fi

if [ "x$ids" = "x" ]; then
	GPG_KEYRING="$GPG --no-default-keyring --keyring $keyring"

	ids=`$GPG_KEYRING --list-keys | sed 's/\// /g' | awk '/^pub/ { print $3 }'`

	# import keys to main keyring
	if [ "x$noimport" = "x" ]; then
		shout "Importing keys from $keyring into default keyring..."
		$GPG_KEYRING --export | $GPG --import
	else
		shout "Skipping import - you should make sure all keys are in your default keyring"
	fi
fi

for myid in $MYKEY $except; do
	ids=`echo $ids | sed "s/ *$myid */ /g"`
done
ids=`echo $ids | sed -e 's/  */ /g' -e 's/^ *//g' -e 's/ *$//g'`


##############################################################################
# main loop

if [ `echo $ids | wc -w` -lt 1 ]; then
	shout 'No keys to sign!'
	cleanup
	exit 0
fi

# give last chance to chicken out
echo "This script's owner:  $OWNER"
echo "Your private key(s):  $MYKEY"
echo "List of keys to sign: $ids"
if [ "x$noask" = "x" ]; then
	shout "Press enter to proceed or Ctrl-C to abort..."
	read p
fi

# check for missing ids in local keyring
unset import_ids
for id in $ids; do
	if ! $GPG --fingerprint $id > /dev/null 2>&1; then
		import_ids="$import_ids $id"
	fi
done

if [ "x$import_ids" != "x" ]; then
	echo "Could not find the following ids in the local keyring:"
	echo "$import_ids"
	if ask "Import missing ids now" y; then
		$GPG --recv-keys $import_ids
	fi
fi

# process all keys
for id in $ids; do
	shout "Now processing key: $id"

	# signing
	if [ "x$nosign" = "x" ]; then
		for myid in $MYKEY; do
			shout "Using your key: $myid"
			$GPG -u $myid --sign-key $id
		done
	else
		shout "Skipping signature creation"
	fi

	# sending to keyserver
	if [ "x$nosend" = "x" ]; then
		shout "Sending key $id to keyserver..."
		$GPG --send-key $id
	else
		shout "Skipping send to keyserver"
	fi

	# sending by email
	if [ "x$nomail" = "x" ]; then
		address=`$GPG --list-key $id | egrep '<.*>' | sed 's/^.*<\(.*\)>.*$/\1/g' | head -1`
		if [ "x$address" = "x" ]; then
			shout "No email address for key $id:"
			$GPG --list-key $id
			if [ "x$noask2" = "x" ]; then
				shout -n "Enter email address for key $id: "
				read address
			fi
		fi
		if [ "x$address" != "x" ]; then
			if [ "$noask" ] || \
			   ask "Send key $id to $address" n; then
				shout "Sending key $id to $address"
				mail_key $id $address
			else
				shout "No email sent to owner of key $id"
			fi
		else
			shout "Will not send email to owner of key $id - no address given"
		fi
	else
		shout "Skipping mail"
	fi
done

# clean up and update trustdb
cleanup
if [ "x$noupdate" = "x" ]; then
	shout "Updating trustdb - this could take a while..."
	gpg --update
else
	shout "Skipping trustdb update - you should run gpg --update-trustdb manually."
fi
shout "Done."
