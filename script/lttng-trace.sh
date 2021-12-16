#just in case
sudo lttng destroy || true

mkdir $1/lttng-storage

if [ -d /mnt/usb ]; then
  sudo mount --bind /mnt/usb/ $1/lttng-storage
fi

sudo lttng create cpcd-session --output=$1/lttng-storage/cpcd-lttng-trace


sudo lttng enable-channel --kernel    --tracefile-size=10000000 --tracefile-count=10 --session=cpcd-session kernel-channel
sudo lttng enable-channel --userspace --tracefile-size=10000000 --tracefile-count=10 --session=cpcd-session userspace-channel

sudo lttng enable-event --kernel --channel=kernel-channel --all
sudo lttng enable-event --userspace --channel=userspace-channel 'lttng_ust_tracef:*'

sudo lttng start

