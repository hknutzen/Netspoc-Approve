#!/bin/bash

# Abort on unexpected errors.
set -e

PROG=newpolicy
POLICYDB=$(get-netspoc-approve-conf netspocdir)
LOCK=$POLICYDB/LOCK
CURRENT=$POLICYDB/current
NEXT=$POLICYDB/next

msg () {
    echo $@ >&2
}

# false (1): all changes from repository have already been processed
changes_pending () {
    local out
    SRC=$POLICYDB/$POLICY/src
    [ -d $SRC ] || return 0;
    out=$(cvs -n -q update $SRC) || exit 1
    [ -n "$out" ]
}

show_log () {
    cat $LOG
}

show_log_background () {
    msg
    msg "Showing log:"
    tail -n 1 -f $LOG &
    TAIL_PID=$!
    # $LOG is locked during write.
    # If lock bekomes available, we know that writing has finished.
    # Disown before killing the to job to prevent message about finished job.
    flock -s $LOG -c true
    disown $TAIL_PID
    kill $TAIL_PID
}

wait_log_available () {
    [ -f $LOG ] && return 0
    sleep 1
    [ -f $LOG ] && return 0
    return 1
}

# Eventually we need multiple calls to newpolicy
while true; do
    if [ -L $NEXT ] ; then

        POLICY=$(basename $(readlink $NEXT))
        LOG=$POLICYDB/$POLICY/compile.log

        # Filehandle "9" is set below at end of this if-clause.
        # Try to get shared lock.
        # Other instances of this script are allowed to get the lock,
        # but newpolicy isn't.
        if flock -n -s 9 ; then
        
            # We got the lock.
            # newpolicy isn't running.
            if ! changes_pending ; then
                
                # No pending changes in repository.
                # Check if newest policy was processed successfully.
                CPOLICY=$(basename $(readlink $CURRENT || true))
                if [ "$POLICY" = "$CPOLICY" ] ; then
                    msg "Newest changeset is already available as current $POLICY"
                    exit;
                else
                    msg "Newest changeset has already been processed" \
                        " as $POLICY, but processing failed."
                    msg
                    msg "Trying again:"
                    # Start newpolicy again for newest changeset.
                fi 
            fi
        else
            
            # newpolicy is already running
            if ! changes_pending ; then
                msg "Newest changeset is currently processed as $POLICY"
                # Check if log is available.
                if wait_log_available ; then
                    show_log_background
                    exit
                fi
                # If log is missing, then possibly newpolicy failed.
                # Restart loop to analyze the new situation.
                continue
            else
                msg "Waiting for processing of $POLICY to be finished"
                # Check if log is available.
                if wait_log_available ; then
                    show_log_background
                    msg "---"
                    # Start another newpolicy for newest changeset.
                else
                    # If log is missing, then possibly newpolicy failed.
                    # Restart loop to analyze the new situation.
                    continue
                fi                    
            fi
        fi
    fi 9<$LOCK 
    
    # Start newpolicy in background. 
    # Disown to prevent it from being terminated if user kills this script.
    $PROG &
    disown -h
    wait $! || status=$?
    if [ "$status" != 2 ] ; then
        exit $status
    fi

    # Another instance of newpolicy is already running.
    # Restart loop to show that output.
done
