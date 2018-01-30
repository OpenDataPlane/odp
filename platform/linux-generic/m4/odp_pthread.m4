##########################################################################
# Check for pthreads availability
##########################################################################

AX_PTHREAD([CC="$PTHREAD_CC"], [
    echo "Error! We require pthreads to be available"
    exit -1
    ])
