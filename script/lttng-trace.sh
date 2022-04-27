#just in case
sudo lttng destroy cpcd-session-executor-`echo $EXECUTOR_NUMBER` || true

sudo lttng create cpcd-session-executor-`echo $EXECUTOR_NUMBER` --output=/home/pi/nfs_storage/lttng-storage/cpcd-lttng-trace-`hostname`-executor-`echo $EXECUTOR_NUMBER`

sudo lttng enable-channel --kernel    --tracefile-size=10000000 --tracefile-count=10 --session=cpcd-session-executor-`echo $EXECUTOR_NUMBER` kernel-channel-executor-`echo $EXECUTOR_NUMBER`
sudo lttng enable-channel --userspace --tracefile-size=10000000 --tracefile-count=10 --session=cpcd-session-executor-`echo $EXECUTOR_NUMBER` userspace-channel-executor-`echo $EXECUTOR_NUMBER`

sudo lttng enable-event --kernel --channel=kernel-channel-executor-`echo $EXECUTOR_NUMBER` --all
sudo lttng enable-event --userspace --channel=userspace-channel-executor-`echo $EXECUTOR_NUMBER` 'lttng_ust_tracef:*'

sudo lttng start cpcd-session-executor-`echo $EXECUTOR_NUMBER`

