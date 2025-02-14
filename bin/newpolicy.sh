#!/bin/bash

# newpolicy.sh -- Prepare configuration from Netspoc for Approve
#
# DESCRIPTION
#
# Prepare latest Netspoc configuration for deployment to devices.
# - create a new directory 'next' in policy db
# - extract newest configuration from repository into 'next'
# - identify the current policy from policy db
# - calculate the next policy tag
# - compile the new policy
# - rename directory 'next' to name of next policy tag
# - mark new policy as current
#
#
# COPYRIGHT AND DISCLAIMER
#
# https://github.com/hknutzen/Netspoc-Approve
# (c) 2025 by Heinz Knutzen <heinz.knutzen@gmail.com>
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

BASE=$(get-netspoc-approve-conf basedir)
GIT_URL=$(get-netspoc-approve-conf netspoc_git)

# Path of policy database.
POLICYDB=$BASE/policies

# The link to current policy.
CURRENT=$POLICYDB/current

# Intermediate name for next policy.
NEXT=$POLICYDB/next

# Bind lockfile to file descriptor.
# File is observed by 'newpolicy'.
exec 9<>$POLICYDB/LOCK

main() {
    # Error code 1 signals, that a process is already running.
    flock -n 9 || exit 1
    uptodate && exit 0
    # Repeatedly try to compile after bad commits have been reverted.
    while true; do
        prepare_next
        if netspoc $PSRC $PCODE; then
            handle_success
        else
            echo Newest changeset failed to compile
            # Mark data as failed for use in 'newpolicy'.
            touch $POLICYDB/failed
            [ "$PREV_POLICY" ] &&
                echo "Left current policy as '$PREV_POLICY'"
            if try_revert; then
                # Revert was successful, try to compile again.
                continue
            fi
        fi
        break
    done
    touch $POLICYDB/LOCK # Used in 'newpolicy'.
    exit 0
}

# true  (0): all changes from repository already have been processed.
# false (1): SRC isn't up to date.
uptodate () {
    (set -e
     DIR=$CURRENT
     [ -d $NEXT ] && DIR=$NEXT
     [ -f "$DIR/src/.git/refs/heads/master" ] || return 1
     cd $DIR/src
     rev1=$(git rev-parse HEAD)
     orig=$(git rev-parse --abbrev-ref @{u} | sed 's/\// /g')
     rev2=$(git ls-remote $orig | cut -f1)
     [ "$rev1" == "$rev2" ]
    )
}

prepare_next() {
    cd $POLICYDB

    # Cleanup leftovers from previous unsuccessful build of this policy.
    rm -rf $NEXT

    # Create temporary directory for new policy.
    mkdir $NEXT

    # Directory and file names of next policy.
    PSRC=$NEXT/src
    PCODE=$NEXT/code
    PLOG=$NEXT/compile.log

    # Log stdout and stderr to file.
    exec >$PLOG 2>&1

    # Change into directory, where files are checked out.
    cd $NEXT

    # Check out newest files from repository into subdirectory "src".
    # Use '--depth 2' for 'git revert' below,
    # as it needs diff to previous commit.
    git clone --quiet --depth 2 $GIT_URL src

    # Read current policy name from POLICY file,
    # which should contain one line: "# p1234 comment ...".
    POLICY_FILE=$PSRC/POLICY
    if [ -e $POLICY_FILE ] ; then
        FCOUNT=$(cat $POLICY_FILE | grep -Po '\d+' | head -n 1)
    fi
    [ "$FCOUNT" ] || FCOUNT=0

    # Read current policy name from symbolic link.
    PREV_POLICY=$(readlink $CURRENT) || true
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
}

# Compiled successfully.
handle_success() {
    # Update POLICY file of current version.
    cd $PSRC
    echo "# $POLICY # Current policy, don't edit manually!" > POLICY
    git add POLICY
    git commit -m $POLICY
    HASH=$(git log -n 1 --format='format:%H')
    git pull --no-rebase --quiet
    git push --quiet
    # Remove pulled commits so we recognize them as new in next run.
    git reset --hard $HASH

    # Move temporary directory to final name.
    cd $POLICYDB
    mv next $POLICY

    # Mark new policy as current.
    rm -f $CURRENT;
    ln -s $POLICY $CURRENT
    echo "Updated current policy to '$POLICY'"

    # Remove 'failed' marker.
    rm -f failed

    # Cleanup previous code directory.
    # Remove huge and no longer used files from pass 1.
    if [ "$PREV_POLICY" ] ; then
        PREV_CODE=$PREV_POLICY/code
        find $PREV_CODE \( -name '*.config' -o -name '*.rules' \) | xargs rm
    fi
}

# Try to revert bad commit, but only if author has an email address.
# This prevents automated commits from newpolicy and from netspoc-api
# from getting reverted.
# Return value: true (0): revert was successful.
try_revert() {
    cd $PSRC
    EMAIL=$(git log -n 1 --format='format:%ae')
    ADMIN_EMAILS=$(get-netspoc-approve-conf admin_emails)
    { git log -n 1 --pretty=short; echo ---; cat $PLOG; } |
        mail -s "Newpolicy failed!" "$EMAIL,$ADMIN_EMAILS"
    # Only revert if systemuser has empty email. Otherwise this
    # script would accidently revert already reverted commit.
    if [ -n "$EMAIL" ] && [ -z $(git config user.email) ]; then
        HASH=$(git log -n 1 --format='format:%H')
        if git revert --no-edit $HASH; then
            git pull --quiet
            git push --quiet
            git log -n 1 --pretty=short $HASH |
                mail -s "Your commit has been reverted" "$EMAIL,$ADMIN_EMAILS"
            return 0
        fi
    fi
    return 1
}

main
