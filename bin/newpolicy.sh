#!/bin/bash

# newpolicy.sh -- Checkout configuration from Netspoc for Approve
#
# DESCRIPTION
#
# Integrates NetSPoC with version control / build management.
# - creates a new directory 'next' in policy db
# - extracts newest configuration from repository into 'next'
# - identifies the current policy from policy db
# - calculates the next policy tag
# - compiles the new policy
# - renames directory 'next' to name of next policy tag
# - marks new policy in policy db as current
#
# COPYRIGHT AND DISCLAIMER
#
# https://github.com/hknutzen/Netspoc-Approve
# (c) 2024 by Heinz Knutzen <heinz.knutzen@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Abort on each error
set -e

BASE=$(get-netspoc-approve-conf basedir)
GIT_URL=$(get-netspoc-approve-conf netspoc_git)

# Path of policy database.
POLICYDB=$BASE/policies

# Link to current policy.
LINK=$POLICYDB/current

# Intermediate name for next policy.
NEXT=$POLICYDB/next

# The lock file for preventing concurrent updates.
LOCK=$POLICYDB/LOCK


# Filehandle "9" is set below at end of this sub shell.
# Set exclusive lock to prevent parallel runs of this script.
(
    # Status code 2 signals, that a process is already running.
    # No error message needed, because this is only called from wrapper script.
    flock -n -e 9 || exit 2

    # We got the lock.

    # Cleanup leftovers from possible previous unsuccessful build of this policy.
    rm -rf $NEXT

    # Create directory for new policy.
    mkdir $NEXT

    # Directory and file names of new policy in policy database.
    PSRC=$NEXT/src
    PCODE=$NEXT/code
    PLOG=$NEXT/compile.log

    # Log stdout and stderr to file.
    exec >$PLOG 2>&1

    # Change into directory, where files are checked out.
    cd $NEXT

    # Check out newest files from repository into subdirectory "src".
    git clone --quiet --depth 1 $GIT_URL src

    # Read current policy name from POLICY file,
    # which should contain one line: "# p1234 comment ...".
    POLICY_FILE=$PSRC/POLICY
    if [ -e $POLICY_FILE ] ; then
        FCOUNT=$(cat $POLICY_FILE | grep -Po '\d+' | head -n 1)
    fi
    [ "$FCOUNT" ] || FCOUNT=0

    # Read current policy name from symbolic link.
    PREV_POLICY=$(readlink $LINK) || true
    if [ "$PREV_POLICY" ] ; then
        LCOUNT=$(echo $PREV_POLICY | grep -Po '\d+' | head -n 1)
    fi
    [ "$LCOUNT" ] || LCOUNT=0

    # Create symlink from new to old code directory,
    # to speed up pass 2 of Netspoc compiler.
    if [ "$PREV_POLICY" ] ; then
        mkdir $PCODE
        ln -s ../../$PREV_POLICY/code $PCODE/.prev
    fi

    # Compare $FCOUNT and $LCOUNT.
    # Typically both values are identical.
    # Take maximum if values are different.
    COUNT=$( [ $FCOUNT -gt $LCOUNT ] && echo $FCOUNT || echo $LCOUNT)

    # Increment counter.
    COUNT=$(expr $COUNT + 1);

    # Get next policy name.
    POLICY=p$COUNT

    # Compile new policy.
    if ! netspoc $PSRC $PCODE; then
        echo New policy failed to compile
        # Mark data as failed for use in wrapper.
        touch $POLICYDB/failed
        [ "$PREV_POLICY" ] && echo "Left current policy as '$PREV_POLICY'"
        # Failure.
        exit 1
    fi

    # Compiled successfully.

    # Update POLICY file of current version.
    cd $PSRC
    echo "# $POLICY # Current policy, don't edit manually!" > POLICY
    git add POLICY
    git commit -m $POLICY
    # This assumes 'git config pull.rebase true' to be set.
    git pull --quiet
    git push --quiet

    # Move temporary directory to final name.
    cd $POLICYDB
    mv next $POLICY

    # Mark new policy as current.
    rm -f $LINK;
    ln -s $POLICY $LINK
    echo "Updated current policy to '$POLICY'"

    # Remove 'failed' marker.
    rm -f failed

    # Cleanup previous code directory.
    # Remove huge and no longer used files from pass 1.
    if [ "$PREV_POLICY" ] ; then
        PREV_CODE=$PREV_POLICY/code
        find $PREV_CODE \( -name '*.config' -o -name '*.rules' \) | xargs rm
    fi

    # Success.
    exit 0
) 9>$LOCK
