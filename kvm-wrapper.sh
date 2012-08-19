#!/bin/sh
#
# KVM Wrapper Script
# Copyright (C) 2011 Benjamin Cohen <bencoh@codewreck.org>
#                    Dominique Martinet <asmadeus@codewreck.org>
# Published under the WTFPLv2 (see LICENSE)
set -e
set -u

SCRIPT_PATH="$0"
SCRIPT_NAME=$(basename $SCRIPT_PATH)
ROOTDIR="/usr/share/kvm-wrapper"
CONFFILE="$ROOTDIR/kvm-wrapper.conf"

canonpath ()
{
	ARG1=${1:-''}
	if [ -z "$ARG1" ]; then
		printf ""
	else
		printf "%s/%s" $(cd $(dirname "$ARG1"); pwd -P) $(basename "$ARG1")
	fi
} # canonpath ()

# Exit on fail and print a nice message
fail_exit ()
{
	printf "\n\n\n"
	while [ $# -gt 0 ]; do
		printf "%s\n" "${1}"
		shift
	done
	printf "Exiting.\n"
	exit 1
} # fail_exit ()

# FS node testers
test_exist ()
{
	local NODE=${1:-''}
	if [ -e "$NODE" ]; then
		return 0
	fi
	return 1
} # test_exist ()

test_dir ()
{
	local DIR=${1:-''}
	if [ -d "$DIR" ] && [ -r "$DIR" ]; then
		return 0
	fi
	return 1
} # test_dir ()

test_dir_rw ()
{
	local DIR=${1:-''}
	if [ -d "$DIR" ] && [ -r "$DIR" ] && [ -w "$DIR" ]; then
		return 0
	fi
	return 1
} # test_dir_rw ()

test_file ()
{
	local FILE=${1:-''}
	if [ -f "$FILE" ] && [ -r "$FILE" ]; then
		return 0
	fi
	return 1
} # test_file ()

test_file_rw ()
{
	local FILE=${1:-''}
	if [ -f "$FILE" ] && [ -r "$FILE" ] && [ -w "$FILE" ]; then
		return 0
	fi
	return 1
} # test_file_rw ()

test_pid ()
{
	local PID=${1:-''}
	ps "$PID" &> /dev/null
} # test_pid ()

test_pid_from_file ()
{
	local PID_FILE=${1:-''}
	test_file "$PID_FILE" && test_pid $(cat "$PID_FILE")
} # test_pid_from_file ()

test_socket ()
{
	local FILE=${1:-''}
	if [ -S "$FILE" ] && [ -r "$FILE" ]; then
		return 0
	fi
	return 1
} # test_socket ()

test_socket_rw ()
{
	local FILE=${1:-''}
	if [ -S "$FILE" ] && [ -r "$FILE" ] && [ -w "$FILE" ]; then
		return 0
	fi
	return 1
} # test_socket_rw ()

test_blockdev ()
{
	local FILE=${1:-''}
	if [ -b "$FILE" ] && [ -r "$FILE" ]; then
		return 0
	fi
	return 1
} # test_blockdev ()

test_blockdev_rw ()
{
	local FILE=${1:-''}
	if [ -b "$FILE" ] && [ -r "$FILE" ] && [ -w "$FILE" ]; then
		return 0
	fi
	return 1
} # test_blockdev_rw ()

test_exec ()
{
	local FILE=${1:-''}
	if [ -x "$FILE" ] && [ -r "$FILE" ]; then
		return 0
	fi
	return 1
} # test_exec ()

test_nodename ()
{
	local NODE=${1:-''}
	if [ -n "$NODE" ] && [ "$NODE" != $(hostname -s) ] &&\
		[ -n "$(get_cluster_host "${NODE}")" ]; then
		return 0
	fi
	return 1
} # test_nodename ()

require_exec ()
{
	ARG1=${1:-''}
	if [ -z "${ARG1}" ]; then
		fail_exit "Executable that is required expected, but none given."
	fi
	test_exec "$(which $ARG1)" || fail_exit "$ARG1 not found or not executable"
} # require_exec ()

check_create_dir ()
{
	local DIR=${1:-''}
	if [ -z "${DIR}" ]; then
		fail_exit "Passed an empty string instead of dir name."
	fi
	test_dir_rw "$DIR" || mkdir -p "$DIR"
	test_dir_rw "$DIR" || \
		fail_exit "Couldn't read/write VM PID directory:" "$DIR"
} # check_create_dir()

wait_test_timelimit ()
{
	local PROPER=0
	local ELAPSED=0
	local TIMELIMIT=${1:-''}
	local EVAL_EXPR=${2:-''}
	while [ $ELAPSED -le $TIMELIMIT ]; do
		ELAPSED=$(($ELAPSED+1))
		eval "$EVAL_EXPR" && PROPER=1;
		if [ $PROPER -eq 1 ]; then
			break
		fi
		sleep 1
	done
	printf "%s\n" $ELAPSED
	if [ $PROPER -eq 1 ]; then
		return 0
	fi
	return 1
} # wait_test_timelimit ()

kvm_init_env ()
{
	VM_NAME=${1:-''}
	if [ -z "${VM_NAME}" ]; then
		return 0
	fi
	KVM_CLUSTER_NODE=local
	VM_DESCRIPTOR="$VM_DIR/$VM_NAME-vm"
	MONITOR_FILE="$MONITOR_DIR/$VM_NAME.unix"
	SERIAL_FILE="$SERIAL_DIR/$VM_NAME.unix"

	local vmnamehash=$(printf "%s" "$VM_NAME" | md5sum | cut -d' ' -f1 |\
		awk '{ string=substr($0, 1, 5); print string; }')
	SCREEN_SESSION_NAME="${SCREEN_NAME_PREFIX}kvm-$VM_NAME-$vmnamehash"

	unset PID_FILE
	test_file "$VM_DESCRIPTOR" ||\
		fail_exit "Couldn't open VM $VM_NAME descriptor : $VM_DESCRIPTOR"

	. "$VM_DESCRIPTOR"
	PID_FILE=${PID_FILE:-"$PID_DIR/${KVM_CLUSTER_NODE:-*}:$VM_NAME-vm.pid"}
} # kvm_init_env()

random_mac ()
{
  BASE_MAC=${BASE_MAC:-"52:54:00:ff"}
	local rand1=$(echo "$(hexdump -n 2 -e '/2 "%u"' /dev/urandom) % 256" | bc)
	local rand2=$(echo "$(hexdump -n 2 -e '/2 "%u"' /dev/urandom) % 256" | bc)
	local MACADDRESS=$(printf "%s:%02x:%02x" "$BASE_MAC" "${rand1}" "${rand2}")
	# check if it's not already used..
	grep -R -q "KVM_MACADDRESS=\"$MACADDRESS\"" ${VM_DIR}/*-vm 2>/dev/null &&\
		random_mac || printf "%s" $MACADDRESS
} # random_mac ()

# cluster helpers
hash_string ()
{
	ARG1=${1:-''}
	printf "%s" "$ARG1" | md5sum | awk '{ print $1 }'
} # hash_string ()

set_cluster_host ()
{
	ARG1=${1:-''}
	ARG2=${2:-''}
	eval KVM_CLUSTER_HOSTS_$(hash_string $ARG1)="$ARG2"
} # set_cluster_host ()

get_cluster_host ()
{
	ARG1=${1:-''}
	eval $(printf '${KVM_CLUSTER_HOSTS_%s:-''}' $(hash_string "$ARG1"))
} # get_cluster_host ()

run_remote ()
{
	ARG1=${1:-''}
	HOST=$(get_cluster_host "$ARG1")
	if [ -z "$HOST" ]; then
		fail_exit "Error: Unknown host $ARG1!"
	fi
	shift
	require_exec ssh
	SSH_OPTS=${SSH_OPTS:-"-t"}
	if [ -n "$KVM_CLUSTER_IDENT" ]; then
		SSH_OPTS+=" -i $KVM_CLUSTER_IDENT"
	fi
	echo "ssh $SSH_OPTS $HOST $@"
	ssh $SSH_OPTS "$HOST" $@
} # run_remote()
# NBD helpers
nbd_img_link ()
{
	KVM_IMAGE=${1:-''}
	if [ -z "${KVM_IMAGE}" ]; then
		fail_exit "Image disk expected, but none given."
	fi
	printf "%s/%s-%s" "$NBD_IMG_LINK_DIR" $(basename $KVM_IMAGE)\
		$(canonpath "$KVM_IMAGE" | md5sum | awk '{ print $1 }')
} # nbd_img_link ()

kvm_nbd_connect ()
{
	require_exec "$KVM_NBD_BIN"
	check_create_dir $NBD_IMG_LINK_DIR
	local KVM_IMAGE=${1:-''}

	local KVM_IMAGE_NBD_LINK=$(nbd_img_link "$KVM_IMAGE")
	if [ -h "$KVM_IMAGE_NBD_LINK" ]; then
		fail_exit "Image disk $KVM_IMAGE seems to be connected already."
	fi

	local SUCCESS=0
	local NBD_BLOCKDEV
	for NBD_BLOCKDEV in /dev/nbd*; do
		local NBD_SOCKET_LOCK="/var/lock/qemu-nbd-nbd$i"

		test_blockdev_rw "$NBD_BLOCKDEV" || continue
		test_socket "$NBD_SOCKET_LOCK" && continue

		$KVM_NBD_BIN -c "$NBD_BLOCKDEV" "$KVM_IMAGE"
		ln -s "$NBD_BLOCKDEV" "$KVM_IMAGE_NBD_LINK"

		printf "Connected: %s to %s.\n" "$KVM_IMAGE" "$NBD_BLOCKDEV"
		SUCCESS=1
		break
	done
	if [ $SUCCESS -ne 1 ]; then
		fail_exit "Couldn't connect image disk for some reason."
	fi
} # kvm_nbd_connect ()

kvm_nbd_disconnect ()
{
	require_exec "$KVM_NBD_BIN"
	check_create_dir $NBD_IMG_LINK_DIR
	local KVM_IMAGE=${1:-''}

	local KVM_IMAGE_NBD_LINK=$(nbd_img_link "$KVM_IMAGE")
	if [ ! -h "$KVM_IMAGE_NBD_LINK" ]; then
		fail_exit "Image disk $KVM_IMAGE does not seem to be connected."
	fi
	$KVM_NBD_BIN -d "$KVM_IMAGE_NBD_LINK"
	rm -f "$KVM_IMAGE_NBD_LINK"
} # kvm_nbd_disconnect ()

# LVM helpers
prepare_disks ()
{
	case "$KVM_MANAGE_DISKS" in
		"ACTIVATE_LV")
			for DISK in "$@"; do
				if [ "$DISK" = "/dev/"*"/"* ]; then
					lvchange -ay "$DISK"
				fi
			done
			;;
		"USER_DEFINED")
			USER_PREPARE_DISKS=${USER_PREPARE_DISKS:-''}
			eval "$USER_PREPARE_DISKS"
			;;
	esac;
} # prepare_disks ()

unprepare_disks ()
{
	case "$KVM_MANAGE_DISKS" in
		"ACTIVATE_LV")
			for DISK in "$@"; do
				if [ "$DISK" = "/dev/"*"/"* ]; then
					lvchange -an "$DISK"
				fi
			done
			;;
		"USER_DEFINED")
			USER_UNPREPARE_DISKS=${USER_UNPREPARE_DISKS:-''}
			eval "$USER_UNPREPARE_DISKS"
			;;
	esac;
} # unprepare_disks ()

lvm_create_disk ()
{
	require_exec "$LVM_LVCREATE_BIN"

	LVM_LV_NAME="${LVM_LV_NAME:-"vm.$VM_NAME"}"
	local LVM_LV_SIZE=$(($ROOT_SIZE+${SWAP_SIZE:-0}))
	LVM_PV_NAME=${LVM_PV_NAME:-''}
	eval "$LVM_LVCREATE_BIN --name $LVM_LV_NAME --size $LVM_LV_SIZE \
		$LVM_VG_NAME $LVM_PV_NAME"
	desc_update_setting "KVM_DISK1" "/dev/$LVM_VG_NAME/$LVM_LV_NAME"
} # lvm_create_disk ()

map_disk ()
{
	local DISKDEV=${1:-''}
	if [ -z "${DISKDEV}" ]; then
		fail_exit "Disk device expected, but none given."
	fi
	kpartx -a -p- "$DISKDEV" > /dev/null
	printf "/dev/mapper/%s" $(kpartx -l -p- "$DISKDEV" |\
		grep -m 1 -- "-1.*$DISKDEV" | awk '{ print $1 }')
} # map_disk ()

unmap_disk ()
{
	local DISKDEV=${1:-''}
	if [ -z "${DISKDEV}" ]; then
		fail_exit "Disk device expected, but none given."
	fi
	kpartx -d -p- "$DISKDEV"
} # unmap_disk ()

lvm_mount_disk ()
{
	set -e

	if test_exist "$PID_FILE" ; then
		fail_exit\
			"VM $VM_NAME seems to be running! (PID file $PID_FILE exists)" \
			"You cannot mount disk on a running VM"
	fi

	printf "Attempting to mount first partition of %s\n" $KVM_DISK1
	prepare_disks "$KVM_DISK1"
	PART=$(map_disk "$KVM_DISK1")
	mkdir -p "/mnt/$VM_NAME"
	mount "$PART" "/mnt/$VM_NAME"
	set +e
} # lvm_mount_disk ()

lvm_umount_disk ()
{
	set -e
	printf "unmounting %s\n" "${KVM_DISK1}"
	umount "/mnt/$VM_NAME"
	rmdir "/mnt/$VM_NAME"
	unmap_disk "$KVM_DISK1"
	unprepare_disks "$KVM_DISK1"
	set +e
} # lvm_umount_disk ()

# Change perms. Meant to run forked.
serial_perms_forked ()
{
	while [ ! -e "$SERIAL_FILE" ]; do
		! ps "$$" &> /dev/null && return
		sleep 1
	done
	if [ -n "$SERIAL_USER" ]; then
		chown "$SERIAL_USER" "$SERIAL_FILE"
		chmod 600 "$SERIAL_FILE"
	fi
	if [ -n "$SERIAL_GROUP" ]; then
		chgrp "$SERIAL_GROUP" "$SERIAL_FILE"
		chmod g+rw "$SERIAL_FILE"
	fi
} # serial_perms_forked ()

# VM descriptor helpers
# Overwrite (or create) descriptor setting
desc_update_setting ()
{
	local KEY=${1:-''}
	local VALUE=${2:-''}

	local MATCH="^#*$KEY"
	local NEW="$KEY=\"$VALUE\""
	sed -i -e "0,/$MATCH/ {
		s@$MATCH=\?\(.*\)@$NEW ## \1@g
		$ t
		$ a$NEW
		}" "$VM_DESCRIPTOR"
} # desc_update_setting ()

# Revert descriptor setting modified by this script
desc_revert_setting ()
{
	local KEY=${1:-''}
	sed -i -e "s/^$KEY=[^#]*## /$KEY=/" "$VM_DESCRIPTOR"
} # desc_revert_setting ()

desc_remove_setting ()
{
	local KEY=${1:-''}
	sed -i -e "/^$KEY/d" "$VM_DESCRIPTOR"
} # desc_remove_setting ()

desc_comment_setting ()
{
	local KEY=${1:-''}
	sed -i -e "s/^$KEY/#$KEY/" "$VM_DESCRIPTOR"
} # desc_comment_setting ()

monitor_send_cmd ()
{
	ARG1=${1:-''}
	if [ -z "${ARG1}" ]; then
		fail_exit "Error: monitor expects command to send, yet none given."
	fi
	printf "%s\n" "${ARG1}" | socat STDIN unix:"$MONITOR_FILE"
} # monitor_send_cmd ()

monitor_send_sysrq ()
{
	ARG1=${ARG1:-''}
	if [ -z "${ARG1}" ]; then
		fail_exit "Error: SYSRQ expected, but none given."
	fi
	local SYSRQ="$ARG1"
	monitor_send_cmd "sendkey ctrl-alt-sysrq-$SYSRQ"
} # monitor_send_sysrq ()

# VM Status
kvm_status_from_pid ()
{
	local VM_PID="$@"
	if test_nodename "$KVM_CLUSTER_NODE" ; then
		run_remote "$KVM_CLUSTER_NODE" ps wwp "$VM_PID"
	else
		ps wwp "$VM_PID"
	fi
} # kvm_status_from_pid ()

kvm_status_vm ()
{
	ARG1=${1:-''}
	kvm_init_env "$ARG1"
	test_exist "$PID_FILE" ||\
		fail_exit "Error : $VM_NAME doesn't seem to be running."

	kvm_status_from_pid $(cat "$PID_FILE")
} # kvm_status_vm ()

kvm_status ()
{
	ARG1=${1:-''}
	if [ -z "${ARG1}" ]; then
		fail_exit "VM name expected, but none given."
	fi
	if [ ! "$ARG1" = "all" ]; then
		kvm_status_vm "$ARG1"
	else
		for KVM_CLUSTER_NODE in $(ls -1 $PID_DIR/*-vm.pid| cut -d':' -f1|\
			sed -e 's:.*/::'| sort | uniq); do
			printf "servers on %s:\n" "${KVM_CLUSTER_NODE}"
			kvm_status_from_pid $(cat $PID_DIR/$KVM_CLUSTER_NODE\:*-vm.pid)
		done
	fi
} # kvm_status ()

# MARK1
# Main function : start a virtual machine
kvm_start_vm ()
{
	check_create_dir "$PID_DIR"
	check_create_dir "$MONITOR_DIR"
	check_create_dir "$SERIAL_DIR"

	if [ -z "$KVM_BIN" ]; then
		KVM_BIN="/usr/bin/kvm"
	fi
	require_exec "$KVM_BIN"
	# Defaults
	KVM_DISK1=${KVM_DISK1:-''}
	KVM_DRIVE_OPT=${KVM_DRIVE_OPT:-''}
	KVM_DRIVE1_OPT=${KVM_DRIVE1_OPT:-$KVM_DRIVE_OPT}
	KVM_DISK2=${KVM_DISK2:-''}
	KVM_DRIVE2_OPT=${KVM_DRIVE2_OPT:-$KVM_DRIVE_OPT}
	KVM_DISK3=${KVM_DISK3:-''}
	KVM_DRIVE3_OPT=${KVM_DRIVE3_OPT:-$KVM_DRIVE_OPT}
	KVM_DISK4=${KVM_DISK4:-''}
	KVM_DRIVE4_OPT=${KVM_DRIVE4_OPT:-$KVM_DRIVE_OPT}
	KVM_CDROM=${KVM_CDROM:-''}
	KVM_KERNEL=${KVM_KERNEL:-''}
	KVM_INITRD=${KVM_INITRD:-''}
	KVM_APPEND=${KVM_APPEND:-''}
	KVM_BRIDGE=${KVM_BRIDGE:-''}
	KVM_NETWORK_MODEL=${KVM_NETWORK_MODEL:-'virtio-net-pci'}
	KVM_NETWORK_TYPE=${KVM_NETWORK_TYPE:-''}
	FORCE=${FORCE:-''}
	SERIAL_USER=${SERIAL_USER:-''}
	SERIAL_GROUP=${SERIAL_GROUP:-''}
	# Build KVM Drives (hdd, cdrom) parameters
	local KVM_DRIVES=""
	KVM_DRIVE_IF="${KVM_DRIVE_IF:-ide-hd}"
	KVM_DRIVE1_IF=${KVM_DRIVE1_IF:-$KVM_DRIVE_IF}
	KVM_DRIVE2_IF=${KVM_DRIVE2_IF:-$KVM_DRIVE_IF}
	KVM_DRIVE3_IF=${KVM_DRIVE3_IF:-$KVM_DRIVE_IF}
	KVM_DRIVE4_IF=${KVM_DRIVE4_IF:-$KVM_DRIVE_IF}
	if [ -n "$KVM_DISK1" ] && [ "$KVM_DRIVE1_IF" = 'virtio' ]; then
		KVM_DRIVES+=" -drive if=virtio,id=disk1,file=\"$KVM_DISK1\"$KVM_DRIVE1_OPT"
	elif [ -n "$KVM_DISK1" ]; then
		KVM_DRIVES+=" -drive if=none,id=disk1,file=\"$KVM_DISK1\"$KVM_DRIVE1_OPT \
			-device ${KVM_DRIVE1_IF},drive=disk1"
	fi
	if [ -n "$KVM_DISK2" ] && [ "$KVM_DRIVE2_IF" = 'virtio' ]; then
		KVM_DRIVES+=" -drive if=virtio,id=disk2,file=\"$KVM_DISK2\"$KVM_DRIVE2_OPT"
	elif [ -n "$KVM_DISK2" ]; then
		KVM_DRIVES+=" -drive if=none,id=disk2,file=\"$KVM_DISK2\"$KVM_DRIVE2_OPT \
			-device ${KVM_DRIVE2_IF},drive=disk2"
	fi
	if [ -n "$KVM_DISK3" ] && [ "$KVM_DRIVE3_IF" = 'virtio' ]; then
		KVM_DRIVES+=" -drive if=virtio,id=disk3,file=\"$KVM_DISK3\"$KVM_DRIVE3_OPT"
	elif [ -n "$KVM_DISK3" ]; then
		KVM_DRIVES+=" -drive if=none,id=disk3,file=\"$KVM_DISK3\"$KVM_DRIVE3_OPT \
			-device ${KVM_DRIVE3_IF},drive=disk3"
	fi
	if [ -n "$KVM_DISK4" ] && [ "$KVM_DRIVE4_IF" = 'virtio' ]; then
		KVM_DRIVES+=" -drive if=virtio,id=disk4,file=\"$KVM_DISK4\"$KVM_DRIVE4_OPT"
	elif [ -n "$KVM_DISK4" ]; then
		KVM_DRIVES+=" -drive if=none,id=disk4,file=\"$KVM_DISK4\"$KVM_DRIVE4_OPT \
			-device ${KVM_DRIVE4_IF},drive=disk4"
	fi

	if [ -n "$KVM_CDROM" ]; then
		KVM_DRIVES="$KVM_DRIVES -cdrom \"$KVM_CDROM\""
	fi
	if [ -z "$KVM_DRIVES" ] && [ "$KVM_BOOTDEVICE" != "n" ]; then
		fail_exit \
			"Your VM $VM_NAME should at least use one cdrom or harddisk drive!" \
			"Please check your conf file:" "$VM_DESCRIPTOR"
	fi
	local LINUXBOOT=""
	if [ -n "$KVM_KERNEL" ]; then
		LINUXBOOT="$LINUXBOOT -kernel \"$KVM_KERNEL\""
	fi
	if [ -n "$KVM_INITRD" ]; then
		LINUXBOOT="$LINUXBOOT -initrd \"$KVM_INITRD\""
	fi
	if [ -n "$KVM_APPEND" ]; then
		LINUXBOOT="$LINUXBOOT -append \"$KVM_APPEND\""
	fi

	# If drive is a lv in the main vg, activate the lv
	prepare_disks "$KVM_DISK1" "$KVM_DISK2" "$KVM_DISK3" "$KVM_DISK4"

	# Network scripts
	if [ -z "$KVM_BRIDGE" ]; then
		KVM_BRIDGE="kvmnat"
	fi
	export KVM_BRIDGE
	KVM_NET_SCRIPT="$ROOTDIR/net/kvm"

	# Backwards compatibility
	if [ "${KVM_NETWORK_MODEL}" = "vhost_net" ]; then
		KVM_NETWORK_TYPE=$KVM_NETWORK_MODEL
	fi

	if [ "$KVM_NETWORK_TYPE" = "vhost_net" ]; then
		KVM_NET="-netdev type=tap,id=guest0,script=$KVM_NET_SCRIPT-ifup,\
downscript=$KVM_NET_SCRIPT-ifdown,vhost=on -device virtio-net-pci,\
netdev=guest0,mac=$KVM_MACADDRESS"
	elif [ "$KVM_NETWORK_TYPE" = "vde" ]; then
		if [ ! -d "${KVM_BRIDGE}" ]; then
			fail_exit "KVM_BRIDGE '${KVM_BRIDGE}' doesn't seem to be a socket."
		fi
		KVM_NET="-netdev vde,id=hostnet0,sock=$KVM_BRIDGE \
			-device $KVM_NETWORK_MODEL,netdev=hostnet0,id=net0,\
mac=${KVM_MACADDRESS},multifunction=on"
	else
		KVM_NET="-netdev type=tap,id=guest0,script=$KVM_NET_SCRIPT-ifup,\
downscript=$KVM_NET_SCRIPT-ifdown -device $KVM_NETWORK_MODEL,\
netdev=guest0,mac=$KVM_MACADDRESS"
	fi

	# Monitor/serial devices
	KVM_MONITORDEV="-monitor unix:$MONITOR_FILE,server,nowait"
	KVM_SERIALDEV="-serial unix:$SERIAL_FILE,server,nowait"

	# Build kvm exec string
	local EXEC_STRING="$KVM_BIN \
		-name $VM_NAME,process="kvm-$VM_NAME" \
		-m $KVM_MEM \
		-smp $KVM_CPU_NUM \
		$KVM_NET \
		$KVM_DRIVES \
		$KVM_BOOTDEVICE \
		$KVM_KEYMAP \
		$KVM_OUTPUT \
		$LINUXBOOT \
		$KVM_MONITORDEV \
		$KVM_SERIALDEV \
		-pidfile $PID_FILE \
		$KVM_ADDITIONNAL_PARAMS"

	# More sanity checks : VM running, monitor socket existing, etc.
	if [ -z "$FORCE" ]; then
		if test_exist "$PID_FILE"; then
			fail_exit "VM $VM_NAME seems to be running already." \
				"PID file $PID_FILE exists"
		fi
		rm -rf "$MONITOR_FILE"
		rm -rf "$SERIAL_FILE"
		if test_socket "$MONITOR_FILE"; then
			fail_exit \
				"Monitor socket $MONITOR_FILE already existing and couldn't be removed"
		fi
		if test_socket "$SERIAL_FILE"; then
			fail_exit \
				"Serial socket $SERIAL_FILE already existing and couldn't be removed"
		fi

		# Fork change_perms
		if [ -n "$SERIAL_USER" ] || [ -n "$SERIAL_GROUP" ]; then
			serial_perms_forked &
		fi
	fi

	# Now run kvm
	printf "%s\n\n" $EXEC_STRING
	eval $EXEC_STRING

	# Cleanup files
	rm -rf "$PID_FILE"
	rm -rf "$MONITOR_FILE"
	rm -rf "$SERIAL_FILE"

	# If drive is a lv in the main vg, deactivate the lv
	unprepare_disks "$KVM_DISK1" "$KVM_DISK2" "$KVM_DISK3" "$KVM_DISK4"

	# Exit
	return 0
} # kvm_start_vm ()

kvm_stop_vm ()
{
	test_exist "$PID_FILE" || fail_exit \
		"VM $VM_NAME doesn't seem to be running.\nPID file $PID_FILE not found"
	test_socket_rw "$MONITOR_FILE" || fail_exit \
		"Monitor socket $MONITOR_FILE not existing or not writable"

	KVM_WAIT_SHUTDOWN=${KVM_WAIT_SHUTDOWN:-20}

	# Send monitor command through unix socket
	printf \
		"Trying to powerdown the VM %s first, might take some time (up to %s sec)\n" \
		$VM_NAME $KVM_WAIT_SHUTDOWN

	monitor_send_cmd "system_powerdown"
	printf "Waiting ..."

	# Now wait for it
	local ELAPSED=0
	local PROPER=0
	ELAPSED=$(wait_test_timelimit $KVM_WAIT_SHUTDOWN\
		"! test_file $PID_FILE") || PROPER=1
	printf " elapsed time : %s sec\n" "$ELAPSED"

	if [ $PROPER -eq 0 ]; then
		printf "VM powerdown properly :)\n"
	else

		printf "Trying with magic-sysrq ... (10sec)\n"
		monitor_send_sysrq r && sleep 2
		monitor_send_sysrq e && sleep 2
		monitor_send_sysrq i && sleep 2
		monitor_send_sysrq s && sleep 2
		monitor_send_sysrq u && sleep 2
		monitor_send_sysrq o && sleep 2

		if test_file "$PID_FILE" ; then
			printf "Trying to monitor-quit the qemu instance.\n"
			monitor_send_cmd "quit" && sleep 2

			if test_file "$PID_FILE"; then
				# kill - SIGTERM
				local KVM_PID=$(cat $PID_FILE)
				printf "Now trying to terminate (SIGTERM) %s, pid %s\n" \
					$KVM_PID $VM_NAME
				kill "$KVM_PID"
			fi # if test_file "$PID_FILE"; then
		fi # if test_file "$PID_FILE" ; then
	fi # if [ $PROPER -eq 0 ]; then

	if ! test_file "PID_FILE"; then
		printf "VM %s is now down.\n" $VM_NAME
	fi

	return 0
} # kvm_stop_vm ()

kvm_run_disk ()
{
	require_exec "$KVM_BIN"
	KVM_DISK1=${1:-''}
	prepare_disks "$KVM_DISK1"
	test_file_rw "$KVM_DISK1" || \
		fail_exit "Couldn't read/write image file:" "$KVM_DISK1"

	# Build kvm exec string
	local EXEC_STRING="$KVM_BIN -net nic,model=$KVM_NETWORK_MODEL,\
macaddr=$KVM_MACADDRESS -net tap -hda $KVM_DISK1 -boot c $KVM_KEYMAP \
$KVM_OUTPUT $KVM_ADDITIONNAL_PARAMS"
	eval "$EXEC_STRING"

	unprepare_disks "$KVM_DISK1"

	return 0
} # kvm_run_disk ()

kvm_start_screen ()
{
	check_create_dir "$RUN_DIR"
	$SCREEN_START_ATTACHED "$SCREEN_SESSION_NAME" $SCREEN_EXTRA_OPTS \
		"$SCRIPT_PATH" start-here "$VM_NAME"
} # kvm_start_screen ()

kvm_start_screen_detached ()
{
	$SCREEN_START_DETACHED "$SCREEN_SESSION_NAME" $SCREEN_EXTRA_OPTS \
		"$SCRIPT_PATH" start-here "$VM_NAME"
} # kvm_start_screen_detached ()

kvm_attach_screen ()
{
	if ! test_exist "$PID_FILE"; then
		fail_exit "Error : $VM_NAME doesn't seem to be running."
	fi
	$SCREEN_ATTACH "$SCREEN_SESSION_NAME" $SCREEN_EXTRA_OPTS
} # kvm_attach_screen ()

kvm_monitor ()
{
	if ! test_exist "$PID_FILE"; then
		fail_exit "Error : $VM_NAME doesn't seem to be running."
	fi
	if ! test_socket_rw "$MONITOR_FILE"; then
		fail_exit "Error : could not open monitor socket $MONITOR_FILE."
	fi
	printf "Attaching monitor unix socket (using socat). Press ^D (EOF) to exit\n"\
		1>&2
	local socatin="-"
	tty >/dev/null 2>&1 && socatin="READLINE"
	socat $socatin unix:"$MONITOR_FILE"
	printf "Monitor exited\n" 1>&2
} # kvm_monitor ()

kvm_serial ()
{
	! test_exist "$PID_FILE" && \
		fail_exit "Error : $VM_NAME doesn't seem to be running."

	! test_socket_rw "$SERIAL_FILE" && \
		fail_exit "Error : could not open serial socket $SERIAL_FILE."

	printf "Attaching serial console unix socket (using socat). Press ^] to exit\n"\
		1>&2
	RC=0
	local socatin="-"
	tty >/dev/null 2>&1\
		&& socatin="-,IGNBRK=0,BRKINT=0,PARMRK=0,ISTRIP=0,INLCR=0,IGNCR=0,ICRNL=0,IXON=0,OPOST=1,ECHO=0,ECHONL=0,ICANON=0,ISIG=0,IEXTEN=0,CSIZE=0,PARENB=0,CS8,escape=0x1d"
	socat $socatin unix:"$SERIAL_FILE" || RC=$?
	if [ $RC -ne 0 ]; then
		fail_exit "socat must be of version > 1.7.0 to work"
	fi
	stty sane
	printf "Serial console exited\n" 1>&2
} # kvm_serial ()

kvm_list ()
{
	ARG1=${1:-''}
	printf "Available VM descriptors :\n"
	for file in "$VM_DIR"/*-vm; do
		kvm_init_env $(basename "${file%"-vm"}")
		if [ -z "$ARG1" ] || [ "$ARG1" = "$KVM_CLUSTER_NODE" ]; then
			local VM_STATUS="Halted"
			test_exist "$PID_FILE" && VM_STATUS="Running"
			printf "\t%-20s\t%s\ton %s\n" "$VM_NAME" "$VM_STATUS" \
				"${KVM_CLUSTER_NODE:-'local'}"
		fi
	done
} # kvm_list ()

kvm_edit_descriptor ()
{
	ARG1=${1:-''}
	kvm_init_env "$ARG1"
	test_file "$VM_DESCRIPTOR" && "$EDITOR" "$VM_DESCRIPTOR"
} # kvm_edit_descriptor ()

kvm_create_descriptor ()
{
	VM_NAME=${1:-''}
	ARG2=${2:-''}
	ARG3=${3:-''}
	local DISK_CREATED=0
	local KVM_IMG_DISKNAME=''
	if [ -n $ARG2 ]; then
		require_exec "$KVM_IMG_BIN"
		local KVM_IMG_DISKNAME=$(canonpath "$ARG2")
	fi
	if [ -z $ARG3 ]; then
		DISK_CREATED=1
	else
		printf "Calling kvm-img to create disk image\n"
		local KVM_IMG_DISKSIZE="$ARG3"
		RC=0
		"$KVM_IMG_BIN" create -f "$KVM_IMG_FORMAT" "$KVM_IMG_DISKNAME" \
			"$KVM_IMG_DISKSIZE" || RC=$?
		if [ $RC -eq 0 ]; then
			DISK_CREATED=1
		else
			printf "Failed creating disk. Creating vm anyway.\n"
		fi
	fi

	VM_DESCRIPTOR="$VM_DIR/$VM_NAME-vm"
	if test_exist "$VM_DESCRIPTOR"; then
		fail_exit "Error : $VM_NAME already exists ($VM_DESCRIPTOR found)"
	fi

	touch "$VM_DESCRIPTOR"
	printf "# VM %s file descriptor\n" "$VM_NAME" >> "$VM_DESCRIPTOR"
	printf "# Created : %s on %s by %s\n" $(date) "$HOSTNAME"\
		"$USER" >> "$VM_DESCRIPTOR"
	printf "\n" >> "$VM_DESCRIPTOR"

	awk '/#xxDEFAULTxx#/,0 { print "#" $0}' $CONFFILE |\
		grep -v "#xxDEFAULTxx#" >> "$VM_DESCRIPTOR"

	if [ $DISK_CREATED -eq 1 ]; then
		local HDA_LINE="KVM_DISK1=\"$KVM_IMG_DISKNAME\""
		sed -i "s,##KVM_DISK1,$HDA_LINE,g" "$VM_DESCRIPTOR"
	fi

	sed -i\
		's/#KVM_MACADDRESS="$(random_mac)/KVM_MACADDRESS="'$(random_mac)'/g'\
		"$VM_DESCRIPTOR"
	sed -i\
		's/#KVM_CLUSTER_NODE="$(hostname -s)/KVM_CLUSTER_NODE="'$(hostname -s)'/g'\
		"$VM_DESCRIPTOR"

	printf "VM %s created. Descriptor : %s\n" "$VM_NAME" "$VM_DESCRIPTOR"
} # kvm_create_descriptor ()

kvm_bootstrap_vm ()
{
	ARG1=${1:-''}
	ARG2=${2:-''}
	cleanup()
	{
		set +e
		printf "Cleaning up the mess\n"
		if [ ${#CLEANUP[*]} -gt 0 ]; then
			LAST_ELEMENT=$((${#CLEANUP[*]}-1))
			for i in $(seq $LAST_ELEMENT -1 0); do
				eval ${CLEANUP[$i]}
			done
		fi
	}

	local CLEANUP=( )

	set -e
	trap cleanup EXIT

	require_exec "kpartx"
	check_create_dir "$BOOT_IMAGES_DIR"
	check_create_dir "$CACHE_DIR"
	check_create_dir "$LOGDIR"

	kvm_init_env "$ARG1"

	if test_exist "$PID_FILE" ; then
		fail_exit \
			"Error : $VM_NAME seems to be running. Please stop it before trying to bootstrap it."
	fi

	if [ -n "$ARG2" ]; then
		# The variable is already set in the config file otherwise.
		BOOTSTRAP_DISTRIB="$ARG2"
	fi
	BOOTSTRAP_SCRIPT="$BOOTSTRAP_DIR/$BOOTSTRAP_DISTRIB/bootstrap.sh"
	if ! test_file "$BOOTSTRAP_SCRIPT" ; then
		fail_exit \
			"Couldn't read $BOOTSTRAP_SCRIPT to bootstrap $VM_NAME as $BOOTSTRAP_DISTRIB"
	fi

	. "$BOOTSTRAP_SCRIPT"

	prepare_disks "$KVM_DISK1"
	CLEANUP+=("unprepare_disks \"$KVM_DISK1\"")
	if ! test_blockdev "$KVM_DISK1"; then
		require_exec "$KVM_NBD_BIN"

		if ! test_file "$KVM_DISK1" ; then
			fail_exit \
				"\"$KVM_DISK1\" appears to be neither a blockdev nor a regular file."
		fi

		printf "Attempting to connect the disk image to an nbd device.\n"
		kvm_nbd_connect "$KVM_DISK1"
		CLEANUP+=("kvm_nbd_disconnect \"$KVM_DISK1\"")
		local BOOTSTRAP_DEVICE=$(nbd_img_link "$KVM_DISK1")
		sleep 1 #needed to give time to the nbd to really connect
	else
		local BOOTSTRAP_DEVICE="$KVM_DISK1"
	fi

	printf "Starting to bootstrap %s as %s on disk %s\n" "$VM_NAME" \
		"$BOOTSTRAP_DISTRIB" "$BOOTSTRAP_DEVICE"
	bootstrap_fs "$BOOTSTRAP_DEVICE"
	sync

	cleanup
	trap - EXIT
	set +e

	printf "Bootstrap ended.\n"
	return 0
} # kvm_bootstrap_vm ()

kvm_build_vm ()
{
	local USER_OPTIONS=( )
	EDIT_CONF=""
	while [ "$#" -gt 1 ]; do
		case "$1" in
			"-s"|"--size")
				OPT=${2:-''}
				if [ -z "${OPT}" ]; then
					fail_exit "Argument is expected to '-s'/'--size'."
				fi
				USER_OPTIONS+=("ROOT_SIZE")
				USER_OPTIONS+=("$OPT")
				shift; shift
				;;
			"-m"|"--mem"|"--memory")
				OPT=${2:-''}
				if [ -z "${OPT}" ]; then
					fail_exit "Argument is expected to '-m'/'--mem'/'--memory'."
				fi
				USER_OPTIONS+=("KVM_MEM")
				USER_OPTIONS+=("$OPT")
				shift; shift
				;;
			"-c"|"--cpu"|"--smp")
				OPT=${2:-''}
				if [ -z "${OPT}" ]; then
					fail_exit "Argument is expected to '-c'/'--cpu'/'--smp'."
				fi
				USER_OPTIONS+=("KVM_CPU_NUM")
				USER_OPTIONS+=("$OPT")
				shift; shift
				;;
			"--swap")
				OPT=${2:-''}
				if [ -z "${OPT}" ]; then
					fail_exit "Argument is expected to '--swap'."
				fi
				USER_OPTIONS+=("SWAP_SIZE")
				USER_OPTIONS+=("$OPT")
				shift; shift
				;;
			"-f"|"--flavor")
				OPT=${2:-''}
				if [ -z "${OPT}" ]; then
					fail_exit "Argument is expected to '-f'/'--flavor'."
				fi
				USER_OPTIONS+=("BOOTSTRAP_FLAVOR")
				USER_OPTIONS+=("$OPT")
				shift; shift
				;;
			"-e"|"--edit"|"--edit-conf")
				EDIT_CONF="yes"
				shift
				;;
		esac
	done
	if [ "$#" -ne 1 ]; then
		print_help
		exit 1
	fi

	VM_NAME=${1-''}

	if [ -z "${VM_NAME}" ]; then
		fail_exit "VM name expected, but empty given."
	fi

	if ! test_file "$AUTOCONF_SCRIPT" ; then
		fail_exit "Couldn't read autoconfiguration script $AUTOCONF_SCRIPT"
	fi

	kvm_create_descriptor "$VM_NAME"

	. "$AUTOCONF_SCRIPT"

	if [ ${#USER_OPTIONS[*]} -gt 0 ]; then
		LAST_ELEMENT=$((${#USER_OPTIONS[*]}-2))
		for i in $(seq 0 2 $LAST_ELEMENT); do
			desc_update_setting "${USER_OPTIONS[$i]}" "${USER_OPTIONS[$((i+1))]}"
		done
	fi

	if [ -n "$EDIT_CONF" ]; then
		kvm_edit_descriptor "$VM_NAME"
	fi

	kvm_init_env "$VM_NAME"

	lvm_create_disk "$VM_NAME"
	kvm_bootstrap_vm "$VM_NAME"

	printf "%s\n" "${VM_NAME}" >> "${STARTUP_LIST}"

	printf "Will now start VM %s\n" "${VM_NAME}"
	kvm_start_screen "$VM_NAME"
} # kvm_build_vm ()

kvm_balloon_vm ()
{
	ARG1=${1:-''}
	if [ -z "${ARG1}" ]; then
		fail_exit "Error: balloon expects parameter, but none given."
	fi
	if ! test_exist "$PID_FILE"; then
		fail_exit "Error : $VM_NAME doesn't seem to be running."
	fi
	if ! test_socket_rw "$MONITOR_FILE"; then
		fail_exit "Error : could not open monitor socket $MONITOR_FILE."
	fi
	monitor_send_cmd "balloon ${ARG1}"
} # kvm_balloon_vm ()

kvm_remove ()
{

	if test_exist "$PID_FILE"; then
		fail_exit \
			"Error : $VM_NAME seems to be running. Please stop it before trying to remove it."
	fi

	local DRIVES_LIST=( )
	KVM_DISK1=${KVM_DISK1:-''}
	KVM_DISK2=${KVM_DISK2:-''}
	KVM_DISK3=${KVM_DISK3:-''}
	KVM_DISK4=${KVM_DISK4:-''}
	if [ -n "$KVM_DISK1" ]; then
		DRIVES_LIST+=("$KVM_DISK1")
	fi
	if [ -n "$KVM_DISK2" ]; then
		DRIVES_LIST+=("$KVM_DISK2")
	fi
	if [ -n "$KVM_DISK3" ]; then
		DRIVES_LIST+=("$KVM_DISK3")
	fi
	if [ -n "$KVM_DISK4" ]; then
		DRIVES_LIST+=("$KVM_DISK4")
	fi
	if [ ${#DRIVES_LIST[*]} -gt 0 ]; then
		LAST_ELEMENT=$((${#DRIVES_LIST[*]}-1))
		for i in $(seq $LAST_ELEMENT -1 0); do
			if lvdisplay "${DRIVES_LIST[$i]}" &> /dev/null; then
				if lvremove "${DRIVES_LIST[$i]}"; then
					unset DRIVES_LIST[$i]
				fi
			fi
		done
	fi

	if [ ${#DRIVES_LIST[*]} -gt 0 ]; then
		printf "The VM %s used the following disks (NOT removed by %s) :\n" \
			$VM_NAME $SCRIPT_NAME
		for DRIVE in ${DRIVES_LIST[*]}; do
			printf "@ %s\n" "${DRIVE}"
		done
	fi
	rm -f "$VM_DESCRIPTOR"
	if test_exist "$VM_DESCRIPTOR"; then
		fail_exit "Failed to remove descriptor $VM_DSCRIPTOR."
	fi
} # kvm_remove ()

print_help ()
{
	ARG1=${1:-''}
	case "$ARG1" in
		"create")
			cat<<HCREATE
Usage $SCRIPT_NAME create [flags] virtual-machine

Flags are :
   -c num, --cpu num:      Number of cpu the system should have
   -m size, --mem size:    Specify how much RAM you want the system to have
   -s size, --size size:   Specify how big the disk should be in MB
   -e, --edit:             If you want to edit the descriptor after autoconfig
   --swap size:            Size of the swap in MB
   --flavor name, -f name:  Flavor of the debian release(lenny, squeeze..)

 More to come ?
HCREATE
			;;
		*)
			cat<<HELP
Usage: $SCRIPT_NAME {start|screen|stop} virtual-machine
       $SCRIPT_NAME {attach|monitor|serial} virtual-machine
       $SCRIPT_NAME {save-state|load-state} virtual-machine
       $SCRIPT_NAME migrate virtual-machine dest-node

       $SCRIPT_NAME status [virtual-machine]
       $SCRIPT_NAME list [node]

       $SCRIPT_NAME balloon virtual-machine target_RAM
       $SCRIPT_NAME bootstrap virtual-machine
       $SCRIPT_NAME create [flags] virtual-machine - for a flag list
       $SCRIPT_NAME help create - help contents on create subcommand
       $SCRIPT_NAME create-desc virtual-machine [diskimage [size]]
       $SCRIPT_NAME edit virtual-machine
       $SCRIPT_NAME remove virtual-machine
HELP
			;;
	esac
	exit 2
} # print_help ()

test_dir "$ROOTDIR" || \
	fail_exit "Couldn't open kvm-wrapper's root directory:" "$ROOTDIR"
test_file "$CONFFILE" || \
	fail_exit "Couldn't open kvm-wrapper's configuration file:" "$CONFFILE"

# Load default configuration file
. "$CONFFILE"

test_file "$CLUSTER_CONF" && . "$CLUSTER_CONF"

# Check VM descriptor directory
test_dir "$VM_DIR" || \
	fail_exit "Couldn't open VM descriptor directory:" "$VM_DIR"

ARG1=${1:-''}
ARG2=${2:-''}
case "$ARG1" in
	'list')
		kvm_list "$ARG2"
		exit 0
		;;
	'status')
		if [ -n "$ARG2" ]; then
			kvm_status "$ARG2"
		else kvm_status "all"; fi
		exit 0
		;;
	'rundisk')
		if [ $# -eq 2 ]; then
			kvm_run_disk "$ARG2"
		else print_help; fi
		exit 0
		;;
	'edit')
		if [ $# -eq 2 ]; then
			kvm_edit_descriptor "$ARG2"
		else print_help; fi
		exit 0
		;;
	create-desc*)
		if [ $# -ge 2 ]; then
			kvm_create_descriptor "$ARG2" ${3:-''} ${4:-''}
		else print_help; fi
		exit 0
		;;
	'create'|'build')
		if [ $# -ge 2 ]; then
			shift
			kvm_build_vm $@
		else print_help; fi
		exit 0
		;;
	'help')
		shift
		print_help $@
		exit 0
		;;
esac

if [ -z "${ARG2}" ]; then
	print_help
	exit 1
fi

kvm_init_env "$ARG2"

if test_nodename "$KVM_CLUSTER_NODE" ; then
	RC=0
	run_remote $KVM_CLUSTER_NODE $ROOTDIR/kvm-wrapper.sh $@ || RC=$?
	exit $RC
fi

# Argument parsing
case "$ARG1" in
	'remove')
		if [ $# -eq 2 ]; then
			kvm_remove "$ARG2"
		else print_help; fi
		;;
	'migrate')
		if [ $# -eq 3 ]; then
			if ! test_file "$PID_FILE"; then
				fail_exit "Error : $VM_NAME doesn't seem to be running."
			fi
			if ! test_socket_rw "$MONITOR_FILE"; then
				fail_exit "Error : could not open monitor socket $MONITOR_FILE."
			fi
			if [ "$KVM_CLUSTER_NODE" = $3 ]; then
				fail_exit "Error: $ARG2 already runs on $3!"
			fi
			if [ -z "$(get_cluster_host $3)" ]; then
				fail_exit "Error: Unknown host $3!"
			fi
			desc_update_setting "KVM_CLUSTER_NODE" "$3"
			random=$(hexdump -n 2 -e '/2 "%u"' /dev/urandom)
			PORT=$((random%1000+4000))
			"$SCRIPT_PATH" receive-migrate-screen "$ARG2" $PORT
			sleep 1
			monitor_send_cmd "migrate_set_speed 1024m"
#			monitor_send_cmd "migrate \"exec: ssh $(get_cluster_host $3) \
#				socat - unix:$RUN_DIR/migrate-$3.sock\""
			monitor_send_cmd "migrate tcp:$(get_cluster_host $3):$PORT"
			monitor_send_cmd "quit"
		else print_help; fi
		;;
	'receive-migrate')
		if [ $# -eq 3 ]; then
#			KVM_ADDITIONNAL_PARAMS+=" -incoming unix:$RUN_DIR/migrate-$VM_NAME.sock"
			KVM_ADDITIONNAL_PARAMS+=" -incoming tcp:"
			KVM_ADDITIONNAL_PARAMS+="$(get_cluster_host $(hostname -s)):$3"
			FORCE="yes"
			kvm_start_vm "$VM_NAME"
		else print_help; fi
		;;
	'receive-migrate-screen')
		if [ $# -eq 3 ]; then
			$SCREEN_START_DETACHED "$SCREEN_SESSION_NAME" $SCREEN_EXTRA_OPTS \
				"$SCRIPT_PATH" receive-migrate "$VM_NAME" "$3"
			sleep 1
		else print_help; fi
		;;
	'save-state')
		if [ $# -eq 2 ]; then
			if ! test_exist "$PID_FILE"; then
				fail_exit "Error : $VM_NAME doesn't seem to be running."
			fi
			if ! test_socket_rw "$MONITOR_FILE"; then
				fail_exit "Error : could not open monitor socket $MONITOR_FILE."
			fi
			monitor_send_cmd "stop"
			monitor_send_cmd "migrate_set_speed 4095m"
			monitor_send_cmd \
				"migrate \"exec:gzip -c > /var/cache/kvm-wrapper/$ARG2-state.gz\""
			monitor_send_cmd "quit"
		else print_help; fi
		;;
	'load-state')
		if [ $# -eq 2 ]; then
			check_create_dir "$RUN_DIR"
			$SCREEN_START_ATTACHED "$SCREEN_SESSION_NAME" $SCREEN_EXTRA_OPTS \
				"$SCRIPT_PATH" load-state-here "$VM_NAME"
		else print_help; fi
		;;
	'load-state-here')
		if [ $# -eq 2 ]; then
			KVM_ADDITIONNAL_PARAMS+=" -incoming \"exec: gzip -c -d /var/cache/kvm-wrapper/$ARG2-state.gz\""
			FORCE="yes"
			kvm_start_vm "$ARG2"
		else print_help; fi
		;;
	'balloon')
		if [ $# -eq 3 ]; then
			ARG3=${3:-''}
			kvm_balloon_vm "$ARG3"
		else print_help; fi
		;;
	'restart')
		if [ $# -eq 2 ]; then
			kvm_stop_vm "$ARG2"
			kvm_start_screen "$ARG2"
		else print_help; fi
		;;
	'start')
		if [ $# -eq 2 ]; then
			kvm_start_screen "$ARG2"
		else print_help; fi
		;;
	'start-here')
		if [ $# -eq 2 ]; then
			kvm_start_vm "$ARG2"
		else print_help; fi
		;;
	'screen')
		if [ $# -eq 2 ]; then
			kvm_start_screen_detached "$ARG2"
		else print_help; fi
		;;
	'attach')
		if [ $# -eq 2 ]; then
			kvm_attach_screen "$ARG2"
		else print_help; fi
		;;
	'monitor')
		if [ $# -eq 2 ]; then
			kvm_monitor "$ARG2"
		else print_help; fi
		;;
	'serial')
		if [ $# -eq 2 ]; then
			kvm_serial "$ARG2"
		else print_help; fi
		;;
	'stop')
		if [ $# -eq 2 ]; then
			kvm_stop_vm "$ARG2"
		else print_help; fi
		;;
	'bootstrap')
		if [ $# -ge 2 ]; then
			kvm_bootstrap_vm "$ARG2" ${3:-''}
		else print_help; fi
		;;
	'create-disk')
		lvm_create_disk "$ARG2"
		;;
	'mount-disk')
		lvm_mount_disk "$ARG2"
		;;
	'umount-disk')
		lvm_umount_disk "$ARG2"
		;;
	*)
		print_help
		;;
esac

