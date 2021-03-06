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
HOSTNAME=${HOSTNAME:-$(hostname -f)}
EDITOR=${EDITOR:-""}
DELIM=";#DLM#;"

get_kvm_disk()
{
	local config=${1:-''}
	local i=${2:-''}
	if [ -z "$config" ] || [ -z "$2" ]; then
		return 1
	fi
	grep -E -e "^KVM_DISK${i}=" "${config}" | awk -F'"' '{ print $2 }'
}

fnmatch()
{
	local arg1=${1:-''}
	local arg2=${2:-''}
	case "$arg2" in $arg1) return 0;; *) return 1;; esac
}

parse_disks()
{
	local config=${1:-''}
	local i=${2:-''}
	if [ -z "$i" ] || [ -z "$config" ]; then
		return 1
	fi
	# KVM_DISKx = path to image, can't be empty
	# KVM_DRIVEx_IF = drive interface, can't be empty
	# KVM_DRIVEx_OPT = options, can be empty
	local glue_disk="KVM_DISK${i}"
	local glue_drvif="KVM_DRIVE${i}_IF"
	local glue_drvopt="KVM_DRIVE${i}_OPT"
	#
	local kvm_disk=""
	local kvm_drvif="ide-hd"
	local kvm_drvopt=""
	for LINE in $(grep -E \
		-e "^${glue_disk}=" \
		-e "^${glue_drvif}=" \
		-e "^${glue_drvopt}=" \
		"${config}"); do
		if fnmatch "${glue_disk}=*" "${LINE}"; then
			kvm_disk=$(printf -- "%s" "${LINE}" | \
				awk -F'"' '{ print $2 }')
		elif fnmatch "${glue_drvif}=*" "${LINE}"; then
			kvm_drvif=$(printf -- "%s" "${LINE}" | \
				awk -F'"' '{ print $2 }')
		elif fnmatch "${glue_drvopt}=*" "${LINE}"; then
			kvm_drvopt=$(printf -- "%s" "${LINE}" | \
				awk -F'"' '{ print $2 }')
		else
			# Don't print-out garbage
			# printf -- "U: '%s'\n" "${LINE}"
			true
		fi
	done

	if [ -z "$kvm_disk" ]; then
		return 0
	fi
	if [ -z "$kvm_drvif" ]; then
		return 1
	fi
	if [ "$kvm_drvif" = 'virtio' ]; then
		printf " -drive if=virtio,id=disk%i,file=\"%s\"%s" \
			"$i" "${kvm_disk}" "${kvm_drvopt}"
	else
		printf " -drive if=none,id=disk%i,file=\"%s\"%s -device %s,drive=disk%i" \
			"$i" "${kvm_disk}"  "${kvm_drvopt}" "${kvm_drvif}" "$i"
	fi
}

parse_network()
{
	local config=${1:-''}
	local i=${2:-''}
	# KVM_NETWORKx_MACADDR =~ MAC address :)
	# KVM_NETWORKx_MODEL =~ eg. virtio-net-pci, e1000
	# KVM_NETWORKx_TYPE =~ actually br type, eg. ovs
	# KVM_NETWORKx_OPT =~ opts to dev
	# KVM_BRIDGEx =~ eg. br0
	# KVM_BRIDGEx_OPT =~ options, eg. 'trunk=0,100'
	# KVM_NET_SCRIPT =~ internal thing, path to ifup/down
	local glue_mac="KVM_NETWORK${i}_MACADDR"
	local glue_net_model="KVM_NETWORK${i}_MODEL"
	local glue_net_type="KVM_NETWORK${i}_TYPE"
	local glue_net_opt="KVM_NETWORK${i}_OPT"
	local glue_br="KVM_BRIDGE${i}"
	local glue_bropt="KVM_BRIDGE${i}_OPT"
	#
	local net_mac=""
	local net_model=""
	local net_type=""
	local net_opt=""
	local br=""
	local br_opt=""
	local kvm_net_script="${ROOTDIR}/net/${VM_NAME}-${i}"
	for LINE in $(grep -E \
		-e "^${glue_mac}=" \
		-e "^${glue_net_model}=" \
		-e "^${glue_net_type}=" \
		-e "^${glue_net_opt}=" \
		-e "^${glue_br}=" \
		-e "^${glue_bropt}" \
		"${config}"); do
		if fnmatch "${glue_mac}=*" "${LINE}"; then
			net_mac=$(printf -- "%s" "${LINE}" | \
				awk -F'"' '{ print $2 }')
		elif fnmatch "${glue_net_model}=*" "${LINE}"; then
			net_model=$(printf -- "%s" "${LINE}" | \
				awk -F'"' '{ print $2 }')
		elif fnmatch "${glue_net_type}=*" "${LINE}"; then
			net_type=$(printf -- "%s" "${LINE}" | \
				awk -F'"' '{ print $2 }')
		elif fnmatch "${glue_net_opt}=*" "${LINE}"; then
			net_opt=$(printf -- "%s" "${LINE}" | \
				awk -F'"' '{ print $2 }')
		elif fnmatch "${glue_br}=*" "${LINE}"; then
			br=$(printf -- "%s" "${LINE}" | \
				awk -F'"' '{ print $2 }')
		elif fnmatch "${glue_bropt}=*" "${LINE}"; then
			br_opt=$(printf -- "%s" "${LINE}" | \
				awk -F'"' '{ print $2 }')
		else
			# Don't print-out garbage
			# printf -- "U: '%s'\n" "${LINE}"
			true
		fi
	done

	if [ -z "$net_mac" ]; then
		return 1
	fi
	if [ -z "$net_model" ]; then
		net_model="virtio-net-pci"
	fi
	if [ -z "$net_type" ]; then
		net_type="vhost_net"
	fi
	if [ "$net_model" = "vhost_net" ]; then
		net_type=$net_model
	fi

	if [ "$net_type" = "vhost_net" ]; then
		printf -- " -netdev type=tap,id=guest%i,script=%s-ifup,\
downscript=%s-ifdown,vhost=on -device virtio-net-pci,netdev=guest%i,mac=%s" \
"$i" "$kvm_net_script" "$kvm_net_script" "$i" "$net_mac"
	elif [ "$net_type" = "vde" ]; then
		if [ -z "$br" ]; then
			fail_exit "KVM_BRIDGE${i} not set."
		fi
		if [ ! -d "$br" ]; then
			fail_exit "KVM_BRIDGE '$br' doesn't seem to be a socket."
		fi
		printf -- " -netdev vde,id=hostnet0,sock=%s%s \
-device %s,netdev=hostnet0,id=net%i,mac=%s,multifunction=on%s" \
"$br" "$br_opt" "$net_model" "$i" "$net_mac" "$net_opt"
	elif [ "$net_type" = "ovs" ]; then
		if [ -z "$br" ]; then
			fail_exit "KVM_BRIDGE${i} not set."
		fi
		printf -- " -netdev type=tap,id=guest%i,script=%s-ifup,\
downscript=%s-ifdown -device %s,netdev=guest%i,mac=%s" \
"$i" "$kvm_net_script"  "$kvm_net_script" "$net_model" "$i" "$net_mac"
	else
		if [ -z "$br" ]; then
			br="kvmnat"
		fi
		printf -- " -netdev type=tap,id=guest%i,script=%s-ifup,\
downscript=%s-ifdown -device %s,netdev=guest%i,mac=%s" \
"$i" "$kvm_net_script" "$kvm_net_script" "$net_model" "$i" "$net_mac"
	fi
	rm -f "${kvm_net_script}-ifup" 2>/dev/null || true
	rm -f "${kvm_net_script}-ifdown" 2>/dev/null || true
	ln -s "${ROOTDIR}/net/kvm-ifup" "${kvm_net_script}-ifup"
	ln -s "${ROOTDIR}/net/kvm-ifdown" "${kvm_net_script}-ifdown"
}

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
	printf "\n"
	while [ $# -gt 0 ]; do
		printf "%s\n" "${1}"
		shift
	done
	if [ -n "${KVM_SCREEN:-''}" ]; then
		local USE_PID_FILE=""
		if ! test_exist "$PID_FILE" ; then
			USE_PID_FILE="true"
			printf "error\n" > "$PID_FILE"
		fi
		printf "Press ^D or enter to exit"
		read UINPUT
		if [ -n "$USE_PID_FILE" ]; then
			rm -f "$PID_FILE"
		fi
	fi
	printf "Exiting.\n"
	exit 1
} # fail_exit ()

# Check whether EDITOR var is set
test_editor()
{
	if [ -z "${EDITOR}" ]; then
		fail_exit "Please set the EDITOR envvar to your favourite editor."
	fi
}

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
	ps "$PID" > /dev/null 2>&1
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
	if [ -n "$NODE" ] && [ "$NODE" != "$(hostname -s)" ] &&\
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
	KVM_CLUSTER_NODE=${KVM_CLUSTER_MODE:-'local'}
	VM_DESCRIPTOR="$VM_DIR/$VM_NAME-vm"
	MONITOR_FILE="$MONITOR_DIR/$VM_NAME.unix"
	SERIAL_FILE="$SERIAL_DIR/$VM_NAME.unix"

	local vmnamehash=$(printf "%s" "$VM_NAME" | md5sum | cut -d' ' -f1 |\
		awk '{ string=substr($0, 1, 5); print string; }')
	SCREEN_SESSION_NAME="${SCREEN_NAME_PREFIX}kvm-$VM_NAME-$vmnamehash"

	unset PID_FILE
	test_file "$VM_DESCRIPTOR" ||\
		fail_exit "Couldn't open VM $VM_NAME descriptor: $VM_DESCRIPTOR"

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
	grep -R -q "KVM_NETWORK[0-9]+_MACADDR=\"$MACADDRESS\"" \
		${VM_DIR}/*-vm 2>/dev/null &&\
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
		SSH_OPTS="${SSH_OPTS} -i $KVM_CLUSTER_IDENT"
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

# PCI assign helper(pci-stub)
pci_stubify ()
{
	local PCIDOMAIN=${1:-''}
	if [ "$(printf -- "%s" "$PCIDOMAIN" | tr -dc ":" | wc -c)" = "1" ]; then
		PCIDOMAIN="0000:$PCIDOMAIN"
	fi

	local PCI_STUB_DRIVER="/sys/bus/pci/drivers/pci-stub"

	# In case pci-stub is not loaded
	test_file_rw "${PCI_STUB_DRIVER}/new_id" || modprobe pci-stub
	test_file_rw "${PCI_STUB_DRIVER}/new_id" || \
		fail_exit "pci-stub driver not available"

	# Retrieve vendor/device id
	local PCIVENDOR="$(cat "/sys/bus/pci/devices/$PCIDOMAIN/vendor" | \
		sed 's/^0x//')"
	PCIVENDOR="${PCIVENDOR} $(cat "/sys/bus/pci/devices/$PCIDOMAIN/device" | \
		sed 's/^0x//')"

	printf "Unbinding pci device (%s [%s]) and binding to pci-stub\n" \
		"$PCIDOMAIN" "$PCIVENDOR"

	# Add id, unbind, and bind
	printf -- "%s\n" "$PCIVENDOR" > "$PCI_STUB_DRIVER/new_id"
	printf -- "%s\n" "$PCIDOMAIN" > "/sys/bus/pci/devices/$PCIDOMAIN/driver/unbind"
	printf -- "%s\n" "$PCIDOMAIN" > "$PCI_STUB_DRIVER/bind"
}

# Change perms. Meant to run forked.
serial_perms_forked ()
{
	while [ ! -e "$SERIAL_FILE" ]; do
		! ps "$$" > /dev/null 2>&1 && return
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
		fail_exit "Error: $VM_NAME doesn't seem to be running."

	local VM_PID=$(cat "$PID_FILE" 2>/dev/null)
	if [ "$VM_PID" = "error" ]; then
		printf "VM %s is in error state, attach it for more info.\n" \
			"$VM_NAME"
	else
		kvm_status_from_pid "$VM_PID"
	fi
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
		ls "$PID_DIR"/*-vm.pid >/dev/null 2>&1 ||\
			fail_exit "No VMs to get status about."

		for KVM_CLUSTER_NODE in $(ls -1 $PID_DIR/*-vm.pid| cut -d':' -f1|\
			sed -e 's:.*/::'| sort | uniq); do
			printf "VMs on %s:\n" "$KVM_CLUSTER_NODE"
			kvm_status_from_pid $(cat \
				"$PID_DIR/$KVM_CLUSTER_NODE:"*-vm.pid 2>/dev/null | \
				grep -v 'error')

			printf "\n"
			for TMP_VM in $(grep -l 'error' \
				"$PID_DIR/$KVM_CLUSTER_NODE:"*-vm.pid 2>/dev/null | \
				sed -e 's!.*:\(.*\)-vm.pid!\1!'); do
				printf "VM %s is in error state, attach it for more info\n" \
					"$TMP_VM"
			done

		done
	fi
} # kvm_status ()

kvm_top()
{
	local nodelist="{local,$KVM_CLUSTER_NODE}"
	local pattern="$PID_DIR/$nodelist:*-vm.pid"
	pidlist=$(eval cat -- "$pattern" 2>/dev/null | sed -e ':a;N;s/\n/,/;ta')
	top -d 2 -cp $pidlist
}

# MARK1
# Main function: start a virtual machine
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
	KVM_CDROM=${KVM_CDROM:-''}
	KVM_KERNEL=${KVM_KERNEL:-''}
	KVM_INITRD=${KVM_INITRD:-''}
	KVM_APPEND=${KVM_APPEND:-''}
	FORCE=${FORCE:-''}
	SERIAL_USER=${SERIAL_USER:-''}
	SERIAL_GROUP=${SERIAL_GROUP:-''}
	# Build KVM Drives (hdd, cdrom) parameters
	local KVM_DRIVES=""
	local KVM_NET=""
	local LIST_KVM_DISKS=""

	for I in $(awk '{ if ($1 !~ /^KVM_DISK[0-9]+=/) { next; }; \
		printf("%02i\n", substr($1, 9, (index($1, "=") - 9))); }' \
		"${VM_DESCRIPTOR}" | sort); do 
		I=$(printf -- "%s" "$I" | awk '{ printf("%01i", $1); }')
		KVM_DRIVES="${KVM_DRIVES}$(parse_disks "${VM_DESCRIPTOR}" $I)"
		KVM_DISK_TMP=$(get_kvm_disk "${VM_DESCRIPTOR}" $I)
		if [ -z "$LIST_KVM_DISKS" ]; then
			LIST_KVM_DISKS="$KVM_DISK_TMP"
		else
			LIST_KVM_DISKS="${LIST_KVM_DISKS} ${KVM_DISK_TMP}"
		fi
	done

	if [ -n "$KVM_CDROM" ]; then
		KVM_DRIVES="${KVM_DRIVES} -cdrom \"$KVM_CDROM\""
	fi
	if [ -z "$KVM_DRIVES" ] && ! printf -- "%s" "$KVM_BOOTDEVICE" | \
	   	grep -q -i -E -e 'order=[a-z]*n[a-z]*(,)?'; then
		fail_exit \
			"Your VM $VM_NAME should at least use one cdrom, harddisk drive or netboot!" \
			"Please, check your conf file:" "$VM_DESCRIPTOR"
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
	prepare_disks "$LIST_KVM_DISKS"

	for I in $(awk '{ if ($1 !~ /^KVM_NETWORK[0-9]+_MACADDR=/) { next; }; \
		printf("%02i\n", substr($1, 12, (index($1, "=") - 12))); }' \
		"${VM_DESCRIPTOR}" | sort); do 
		I=$(printf -- "%s" "$I" | awk '{ printf("%01i", $1); }')
		KVM_NET="${KVM_NET}$(parse_network "${VM_DESCRIPTOR}" $I)"
	done

	# PCI passthrough assignement
	local KVM_PCI_ASSIGN=""
	for PCI_DOMAIN_TMP in $(grep -E -e '^KVM_PCIASSIGN[0-9]+_DOMAIN="' \
		"$VM_DESCRIPTOR"); do
		local pci_domain=$(printf -- "%s" "$PCI_DOMAIN_TMP" | \
			awk -F'"' '{ print $2 }')
		local i=$(printf -- "%s" "$PCI_DOMAIN_TMP" | \
			awk '{ print substr($1, 14, (index($1, "=") - 14)); }')
		local pci_id=$(grep -E -e "^KVM_PCIASSIGN${i}_ID=" \
			"$VM_DESCRIPTOR");
		pci_stubify "$pci_domain"
		if [ -z "$pci_id" ]; then
			pci_id="pciassign${i}"
		fi
		KVM_PCI_ASSIGN="${KVM_PCI_ASSIGN} -device pci-assign,id=${pci_id},host=${pci_domain}"
	done

	# Monitor/serial devices
	KVM_MONITORDEV="-monitor unix:$MONITOR_FILE,server,nowait"
	KVM_SERIALDEV="-serial unix:$SERIAL_FILE,server,nowait"

	# Build kvm exec string
	local EXEC_STRING="$KVM_BIN \
		-name $VM_NAME,process="kvm-$VM_NAME" \
		-m $KVM_MEM \
		-smp $KVM_CPU_NUM \
		$KVM_PCI_ASSIGN \
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

	# More sanity checks: VM running, monitor socket existing, etc.
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
	local KVM_RETVAL=0
	eval "$EXEC_STRING" || KVM_RETVAL=1

	# Cleanup files
	rm -rf "$PID_FILE"
	rm -rf "$MONITOR_FILE"
	rm -rf "$SERIAL_FILE"
	rm -rf "${ROOTDIR}/net/${VM_NAME}-"*"-ifup"
	rm -rf "${ROOTDIR}/net/${VM_NAME}-"*"-ifdown"

	# If drive is a lv in the main vg, deactivate the lv
	unprepare_disks "$LIST_KVM_DISKS"

	if [ $KVM_RETVAL != 0 ]; then
		fail_exit "KVM execution exited with RC ${KVM_RETVAL}"
	fi

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
	printf " elapsed time: %s sec\n" "$ELAPSED"

	if [ $PROPER -eq 0 ]; then
		printf "VM powerdown properly:)\n"
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
	
	local KVM_NETWORK_MACADDR=$(random_mac)
	# Build kvm exec string
	local EXEC_STRING="$KVM_BIN -net nic,model=rtl8139,\
macaddr=${KVM_NETWORK_MACADDR} -net tap -hda $KVM_DISK1 -boot c $KVM_KEYMAP \
$KVM_OUTPUT $KVM_ADDITIONNAL_PARAMS"
	eval "$EXEC_STRING"

	unprepare_disks "$KVM_DISK1"

	return 0
} # kvm_run_disk ()

kvm_start_screen ()
{
	check_create_dir "$RUN_DIR"
	eval KVM_SCREEN="yes" $SCREEN_START_ATTACHED "$SCREEN_SESSION_NAME" \
		$SCREEN_EXTRA_OPTS "$SCRIPT_PATH" start-here "$VM_NAME"
} # kvm_start_screen ()

kvm_start_screen_detached ()
{
	eval KVM_SCREEN="yes" $SCREEN_START_DETACHED "$SCREEN_SESSION_NAME" \
		$SCREEN_EXTRA_OPTS "$SCRIPT_PATH" start-here "$VM_NAME"
} # kvm_start_screen_detached ()

kvm_attach_screen ()
{
	if ! test_exist "$PID_FILE"; then
		fail_exit "Error: $VM_NAME doesn't seem to be running."
	fi
	$SCREEN_ATTACH "$SCREEN_SESSION_NAME" $SCREEN_EXTRA_OPTS
} # kvm_attach_screen ()

kvm_monitor ()
{
	if ! test_exist "$PID_FILE"; then
		fail_exit "Error: $VM_NAME doesn't seem to be running."
	fi
	if ! test_socket_rw "$MONITOR_FILE"; then
		fail_exit "Error: could not open monitor socket $MONITOR_FILE."
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
		fail_exit "Error: $VM_NAME doesn't seem to be running."

	! test_socket_rw "$SERIAL_FILE" && \
		fail_exit "Error: could not open serial socket $SERIAL_FILE."

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

	ls "$VM_DIR"/*-vm >/dev/null 2>&1 || fail_exit "No VMs to list."

	printf "Available VM descriptors:\n"
	for file in "$VM_DIR"/*-vm; do
		kvm_init_env $(basename "${file%"-vm"}")
		if [ -z "$ARG1" ] || [ "$ARG1" = "$KVM_CLUSTER_NODE" ]; then
			local VM_STATUS="Halted"
			local VM_PID=$(cat "$PID_FILE" 2>/dev/null)
			if [ -z "$VM_PID" ]; then
				VM_STATUS="Halted"
			elif [ "$VM_PID" = "error" ]; then
				VM_STATUS="Error"
			else
				VM_STATUS="Running"
			fi
			printf "\t%-20s\t%s\ton %s\n" "$VM_NAME" "$VM_STATUS" \
				"${KVM_CLUSTER_NODE:-'local'}"
		fi
	done
} # kvm_list ()

kvm_edit_descriptor ()
{
	ARG1=${1:-''}
	test_editor
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
		fail_exit "Error: $VM_NAME already exists ($VM_DESCRIPTOR found)"
	fi

	touch "$VM_DESCRIPTOR"
	if ! test_exist "$VM_DESCRIPTOR"; then
		fail_exit "Error: Couldn't create $VM_NAME descriptor ($VM_DSECRIPTOR)"
	fi
	printf "# VM %s file descriptor\n" "$VM_NAME" >> "$VM_DESCRIPTOR"
	printf "# Created: %s on %s by %s\n" $(date) "$HOSTNAME"\
		"$USER" >> "$VM_DESCRIPTOR"
	printf "\n" >> "$VM_DESCRIPTOR"

	awk '/#xxDEFAULTxx#/,0 { print "#" $0}' $CONFFILE |\
		grep -v "#xxDEFAULTxx#" >> "$VM_DESCRIPTOR"

	if [ $DISK_CREATED -eq 1 ]; then
		local HDA_LINE="KVM_DISK1=\"$KVM_IMG_DISKNAME\""
		sed -i "s,##KVM_DISK1,$HDA_LINE,g" "$VM_DESCRIPTOR"
	fi

	sed -i\
		's/#KVM_NETWORK1_MACADDR="`random_mac`/KVM_NETWORK1_MACADDR="'$(random_mac)'/g'\
		"$VM_DESCRIPTOR"
	sed -i\
		's/#KVM_CLUSTER_NODE="`hostname -s`/KVM_CLUSTER_NODE="'$(hostname -s)'/g'\
		"$VM_DESCRIPTOR"

	printf "VM %s created. Descriptor: %s\n" "$VM_NAME" "$VM_DESCRIPTOR"
} # kvm_create_descriptor ()

kvm_bootstrap_vm ()
{
	ARG1=${1:-''}
	ARG2=${2:-''}
	cleanup()
	{
		set +e
		printf "Cleaning up the mess\n"
		IFS="
"
		for C in $(printf -- "$CLEANUP" | sed "s@${DELIM}@\n@g"); do
			eval "$C"
		done
	}

	CLEANUP=""

	set -e
	trap cleanup EXIT

	require_exec "kpartx"
	check_create_dir "$BOOT_IMAGES_DIR"
	check_create_dir "$CACHE_DIR"
	check_create_dir "$LOGDIR"

	kvm_init_env "$ARG1"

	if test_exist "$PID_FILE" ; then
		fail_exit \
			"Error: $VM_NAME seems to be running. Please stop it before trying to bootstrap it."
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
	CLEANUP="${CLEANUP}${DELIM}unprepare_disks \"$KVM_DISK1\""
	if ! test_blockdev "$KVM_DISK1"; then
		require_exec "$KVM_NBD_BIN"

		if ! test_file "$KVM_DISK1" ; then
			fail_exit \
				"\"$KVM_DISK1\" appears to be neither a blockdev nor a regular file."
		fi

		printf "Attempting to connect the disk image to an nbd device.\n"
		kvm_nbd_connect "$KVM_DISK1"
		CLEANUP="${CLEANUP}${DELIM}kvm_nbd_disconnect \"$KVM_DISK1\""
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

kvm_migrate_vm()
{
	local REMOTE_NODE="$2"

	test_file "$PID_FILE" || \
		fail_exit "Error : $VM_NAME doesn't seem to be running."
	test_socket_rw "$MONITOR_FILE" || \
		fail_exit "Error : could not open monitor socket $MONITOR_FILE."
	if [ "$KVM_CLUSTER_NODE" = "${REMOTE_NODE}" ]; then
		fail_exit "Error: $VM_NAME already runs on $REMOTE_NODE!"
	fi
	local rnode=$(get_cluster_host "${REMOTE_NODE}")
	if [ -z "${tmp_rnode}" ]; then
		fail_exit "Error: Unknown host $REMOTE_NODE!"
	fi
	
	# Update VM configuration with new node
	desc_update_setting "KVM_CLUSTER_NODE" "$REMOTE_NODE"
	PORT=$(($(hexdump -n 2 -e '/2 "%u"' /dev/urandom) % 1000 + 4000))

	# Launch new instance (on pre-configured node)
	"$SCRIPT_PATH" receive-migrate "$VM_NAME" "$PORT"

	monitor_send_cmd "migrate_set_speed 1024m"
#	monitor_send_cmd "migrate \"exec: ssh `get_cluster_host $REMOTE_NODE` socat - unix:$RUN_DIR/migrate-$REMOTE_NODE.sock\""
	monitor_send_cmd "migrate tcp:${rnode}:${PORT}"
	monitor_send_cmd "quit"
}

kvm_receive_migrate_vm()
{
	local PORT="$2"

	eval KVM_SCREEN="yes" $SCREEN_START_DETACHED "$SCREEN_SESSION_NAME" \
		$SCREEN_EXTRA_OPTS \
		"$SCRIPT_PATH" receive-migrate-here "$VM_NAME" "$PORT"

	# Wait for the receiving qemu is ready.
	#while ! test_exist $RUN_DIR/migrate-$VM_NAME.sock; do
	while ! netstat -nplt | grep -q ":$PORT "; do
		sleep 1;
	done
}

kvm_receive_migrate_here_vm()
{
	local PORT=${2:-""}

#	KVM_ADDITIONNAL_PARAMS+=" -incoming unix:$RUN_DIR/migrate-$VM_NAME.sock"
	local rnode=$(get_cluster_host $(hostname -s))
	KVM_ADDITIONNAL_PARAMS="${KVM_ADDITIONAL_PARAMS} -incoming tcp::$PORT"
	FORCE="yes"
	kvm_start_vm "$VM_NAME"
}

kvm_save_state_vm()
{
	test_exist "$PID_FILE" || \
		fail_exit "Error : $VM_NAME doesn't seem to be running."
	test_socket_rw "$MONITOR_FILE" || \
		fail_exit "Error : could not open monitor socket $MONITOR_FILE."
	monitor_send_cmd "stop"
	monitor_send_cmd "migrate_set_speed 4095m"
	monitor_send_cmd "migrate \"exec:gzip -c > /var/cache/kvm-wrapper/$VM_NAME-state.gz\""
	monitor_send_cmd "quit"
}

kvm_load_state_vm()
{
	KVM_ADDITIONNAL_PARAMS="${KVM_ADDITIONAL_PARAMS} -incoming \"exec: gzip -c -d /var/cache/kvm-wrapper/$VM_NAME-state.gz\""
	FORCE="yes"
	kvm_start_vm "$2"
}

kvm_build_vm()
{
	local USER_OPTS=""
	EDIT_CONF=""
	while [ "$#" -gt 1 ]; do
		case "$1" in
			"-s"|"--size")
				OPT=${2:-''}
				if [ -z "${OPT}" ]; then
					fail_exit "Argument is expected to '-s'/'--size'."
				fi
				USER_OPTS="${USER_OPTS}${DELIM}ROOT_SIZE=${OPT}"
				shift; shift
				;;
			"-m"|"--mem"|"--memory")
				OPT=${2:-''}
				if [ -z "${OPT}" ]; then
					fail_exit "Argument is expected to '-m'/'--mem'/'--memory'."
				fi
				USER_OPTS="${USER_OPTS}${DELIM}KVM_MEM=${OPT}"
				shift; shift
				;;
			"-c"|"--cpu"|"--smp")
				OPT=${2:-''}
				if [ -z "${OPT}" ]; then
					fail_exit "Argument is expected to '-c'/'--cpu'/'--smp'."
				fi
				USER_OPTS="${USER_OPTS}${DELIM}KVM_CPU_NUM=${OPT}"
				shift; shift
				;;
			"--swap")
				OPT=${2:-''}
				if [ -z "${OPT}" ]; then
					fail_exit "Argument is expected to '--swap'."
				fi
				USER_OPTS="${USER_OPTS}${DELIM}SWAP_SIZE=${OPT}"
				shift; shift
				;;
			"-f"|"--flavor")
				OPT=${2:-''}
				if [ -z "${OPT}" ]; then
					fail_exit "Argument is expected to '-f'/'--flavor'."
				fi
				USER_OPTS="${USER_OPTS}${DELIM}BOOTSTRAP_FLAVOR=${OPT}"
				shift; shift
				;;
			"-e"|"--edit"|"--edit-conf")
				local EDIT_CONF="yes"
				shift
				test_editor
				;;
			"--no-bootstrap")
				local DISABLE_BOOTSTRAP="yes"
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

	IFS="
"
	for ELEMENT in $(printf -- "%s" "$USER_OPTS" | sed "s@${DELIM}@\n@g"); do
		[ -z "${ELEMENT}" ] && continue
		KEY=$(printf -- "%s" "$ELEMENT" | awk -F'=' '{ print $1 }')
		[ -z "$KEY" ] && continue
		VALUE=$(printf -- "%s" "$ELEMENT" | awk \
			'{ arr_len=split($0, arr, "="); \
			for (i=2; i <= arr_len; i++) { \
				printf "%s", arr[i]; \
				if ((i+1) <= arr_len) { printf "=" }; \
			};}')
		desc_update_setting "$KEY" "$VALUE"
	done

	if [ -n "$EDIT_CONF" ]; then
		kvm_edit_descriptor "$VM_NAME"
	fi

	kvm_init_env "$VM_NAME"

	lvm_create_disk "$VM_NAME"
	if [ -z "$DISABLE_BOOTSTRAP" ]; then
		kvm_bootstrap_vm "$VM_NAME"
		printf "Will now start VM %s\n" "${VM_NAME}"
		kvm_start_screen "$VM_NAME"
	else
		printf "VM %s created.\n" "$VM_NAME"
	fi
} # kvm_build_vm ()

kvm_balloon_vm ()
{
	ARG1=${1:-''}
	if [ -z "${ARG1}" ]; then
		fail_exit "Error: balloon expects parameter, but none given."
	fi
	if ! test_exist "$PID_FILE"; then
		fail_exit "Error: $VM_NAME doesn't seem to be running."
	fi
	if ! test_socket_rw "$MONITOR_FILE"; then
		fail_exit "Error: could not open monitor socket $MONITOR_FILE."
	fi
	monitor_send_cmd "balloon ${ARG1}"
} # kvm_balloon_vm ()

kvm_pci_assign_vm ()
{
	! test_exist "$PID_FILE" && \
		fail_exit "Error: $VM_NAME doesn't seem to be running."
	! test_socket_rw "$MONITOR_FILE" && \
		fail_exit "Error: could not open monitor socket $MONITOR_FILE."

	local domain="${1:-''}"
	pci_stubify "$domain"
	local devid=""
	if [ -n "${2:-''}" ]; then
		devid=",id=$2"
	fi

	monitor_send_cmd "device_add pci-assign${devid},host=$domain"
}

kvm_remove_vm()
{
	LIST_KVM_DRIVE_NR=""
	if test_exist "$PID_FILE"; then
		fail_exit \
			"Error: $VM_NAME seems to be running. Please stop it before trying to remove it."
	fi

	for I in $(awk '{ if ($1 !~ /^KVM_DISK[0-9]+=/) { next; }; \
		printf("%02i\n", substr($1, 9, (index($1, "=") - 9))); }' \
		"${VM_DESCRIPTOR}" | sort); do 
		I=$(printf -- "%s" "$I" | awk '{ printf("%01i", $1); }')
		KVM_DRIVE=$(get_kvm_disk "$VM_DESCRIPTOR" $I)
		if [ -z "$KVM_DRIVE" ]; then
			continue
		fi
		if lvdisplay "$KVM_DRIVE" > /dev/null 2>&1 \
			&& lvremove "$KVM_DRIVE" > /dev/null 2>&1; then
			continue
		fi
		if [ -z "$LIST_KVM_DRIVE_NR" ]; then
			LIST_KVM_DRIVE_NR="$KVM_DRIVE"
		else
			LIST_KVM_DRIVE_NR="${LIST_KVM_DRIVE_NR} ${KVM_DRIVE}"
		fi
	done

	if [ -n "$LIST_KVM_DRIVE_NR" ]; then
		printf "The VM %s used the following disks (NOT removed by %s):\n" \
			$VM_NAME $SCRIPT_NAME
		for DRIVE in $LIST_KVM_DRIVE_NR; do
			printf "@ %s\n" "$DRIVE"
		done
	fi
	rm -f "$VM_DESCRIPTOR"
	if test_exist "$VM_DESCRIPTOR"; then
		fail_exit "Failed to remove descriptor $VM_DSCRIPTOR."
	fi
}

kvm_edit_conf()
{
	eval "$EDITOR" "$CONFFILE"
}

print_help ()
{
	ARG1=${1:-''}
	case "$ARG1" in
		"create")
			cat<<HCREATE
Usage $SCRIPT_NAME create [flags] virtual-machine

Flags are:
   -c num, --cpu num:      Number of cpu the system should have
   -m size, --mem size:    Specify how much RAM you want the system to have
   -s size, --size size:   Specify how big the disk should be in MB
   -e, --edit:             If you want to edit the descriptor after autoconfig
   --no-bootstrap:         Do not run bootstrap
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
       $SCRIPT_NAME top
       $SCRIPT_NAME conf

       $SCRIPT_NAME balloon virtual-machine target_RAM
       $SCRIPT_NAME pci-assign virtual-machine pci-domain [devname]
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

if [ $# -eq 0 ]; then
	print_help
	exit 0
fi

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
	'top')
		kvm_top
		exit 0
		;;
	'rundisk')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_run_disk "$ARG2"
		exit 0
		;;
	'edit')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_edit_descriptor "$ARG2"
		exit 0
		;;
	create-desc*)
		if [ $# -lt 2 ]; then
			print_help
		fi
		kvm_create_descriptor "$ARG2" ${3:-''} ${4:-''}
		exit 0
		;;
	'create'|'build')
		if [ $# -lt 2 ]; then
			print_help
		fi
		shift
		kvm_build_vm $@
		exit 0
		;;
	'conf')
		kvm_edit_conf
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
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_remove_vm "$2"
		;;
	'migrate')
		if [ $# -ne 3 ]; then
			print_help
		fi
		kvm_migrate_vm "$2" "$3"
		;;
	'receive-migrate-here')
		if [ $# -ne 3 ]; then
			print_help
		fi
		kvm_receive_migrate_here_vm "$2" "$3"
		;;
	'receive-migrate')
		if [ $# -ne 3 ]; then
			print_help
		fi
		kvm_receive_migrate_vm "$VM_NAME" "$3"
		;;
	'save-state')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_save_state_vm "$2"
		;;
	'load-state')
		if [ $# -ne 2 ]; then
			print_help
		fi
		check_create_dir "$RUN_DIR"
		eval KVM_SCREEN="yes" $SCREEN_START_ATTACHED \
			"$SCREEN_SESSION_NAME" $SCREEN_EXTRA_OPTS \
			"$SCRIPT_PATH" load-state-here "$VM_NAME"
		;;
	'load-state-here')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_load_state_vm "$2"
		;;
	'balloon')
		if [ $# -ne 3 ]; then
			print_help
		fi
		ARG3=${3:-''}
		kvm_balloon_vm "$ARG3"
		;;
	'pci-assign')
		if [ $# -lt 3 ] || [ $# -gt 4 ]; then
			print_help
		fi
		kvm_pci_assign_vm "${3:-''}" "${4:-''}"
		;;
	'restart')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_stop_vm "$ARG2"
		kvm_start_screen "$ARG2"
		;;
	'start')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_start_screen "$ARG2"
		;;
	'start-here')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_start_vm "$ARG2"
		;;
	'screen')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_start_screen_detached "$ARG2"
		;;
	'attach')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_attach_screen "$ARG2"
		;;
	'monitor')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_monitor "$ARG2"
		;;
	'serial')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_serial "$ARG2"
		;;
	'stop')
		if [ $# -ne 2 ]; then
			print_help
		fi
		kvm_stop_vm "$ARG2"
		;;
	'bootstrap')
		if [ $# -lt 2 ]; then
			print_help
		fi
		kvm_bootstrap_vm "$ARG2" ${3:-''}
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

