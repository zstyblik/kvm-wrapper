#!/bin/sh
### BEGIN INIT INFO
# Provides:          kvm-wrapper
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: kcm-wrapper init script
# Description:       This script starts a list of VMs and stops the running
#                    ones when asked to
### END INIT INFO

# -- bencoh, 2009/08/11
# -- Asmadeus, 2011/06

SCRIPTNAME="/etc/init.d/kvm-wrapper"

. "/lib/lsb/init-functions"

KVM_WRAPPER_DIR="/usr/share/kvm-wrapper"
KVM_WRAPPER="${KVM_WRAPPER_DIR}/kvm-wrapper.sh"
KVM_VM_LIST="${KVM_WRAPPER_DIR}/startup/startup-list"

start_vm()
{
	VM_NAME=${1:-''}
	if [ -z "${VM_NAME}" ]; then
		printf "VM name expected, but none given.\n" 1>&2
		return 1
	fi
	log_begin_msg "Starting up VM: $VM_NAME ..."
	EXITNUM=0
	$KVM_WRAPPER screen "$VM_NAME" || EXITNUM=$?
	printf "%s\n" "$EXITNUM"
	case "$EXITNUM" in 
		0) log_end_msg 0 ;;
		*) log_end_msg 1 ;;
	esac
	return 0
} # start_vm()

stop_vm()
{
	VM_NAME=${1:-''}
	if [ -z "${VM_NAME}" ]; then
		printf "VM name expected, but none given.\n" 1>&2
		return 1
	fi
	log_begin_msg "Stopping VM: $VM_NAME ..."
	"$KVM_WRAPPER" stop "$VM_NAME"
	log_end_msg 0
} # stop_vm()

do_start()
{
	if [ ! -f /usr/share/kvm-wrapper/kvm-wrapper.sh ]; then
		log_begin_msg "Mounting /usr/share/kvm-wrapper since it doesn't seem here"
		printf "\n"
		mount /usr/share/kvm-wrapper
		sleep 3
	fi

	printf "cleaning old pid files for %s\n" $(hostname -s)
	rm -vf /usr/share/kvm-wrapper/run/$(hostname -s)*

	for line in $(grep -E -v '^#' "$KVM_VM_LIST"); do
		printf "%s" "${line}" | grep -E -e "^KVM_CLUSTER_NODE=\"?$(hostname -s)" \
			"${KVM_WRAPPER_DIR}/vm/${line}-vm" &> /dev/null && \
			start_vm "$line"
	done
} # do_start()

do_stop()
{
	for vmname in $($KVM_WRAPPER list |\
		grep -E -e "Running[[:space:]]on ($(hostname -s)|local)" |\
		awk '{ print $1 }'); do
		stop_vm "$vmname"
	done
} # do_stop

if [ ! -d "${KVM_WRAPPER_DIR}" ]; then
	printf "Directory '%s' doesn't seem to exist.\n" "${KVM_WRAPPER_DIR}" 1>&2
	return 1
fi
if [ ! -x "${KVM_WRAPPER}" ]; then
	printf "Script '%s' either doesn't exist or is not executable.\n" \
		"${KVM_WRAPPER}" 1>&2
	return 1
fi

ACTION=${1:-''}
case "$ACTION" in
	start)
		log_begin_msg "Autostarting VMs (kvm-wrapper) ..."
		printf "\n"
		do_start
		case "$?" in
			0|1) log_end_msg 0 ;;
			2) log_end_msg 1 ;;
		esac
		;;
	stop)
		log_begin_msg "Shutting down autostarted VMs (kvm-wrapper) ..."
		printf "\n"
		do_stop
		case "$?" in
			0|1) log_end_msg 0 ;;
			2) log_end_msg 1 ;;
		esac
		;;
	restart|force-reload)
		;;
	start-vm)
		VM_NAME=${2:-''}
		if [ -z "${VM_NAME}" ]; then
			printf "VM name expected, but none given.\n" 1>&2
			return 1
		fi
		start_vm "$VM_NAME"
	;;
	*)
		printf "Usage: %s start\n" "${SCRIPTNAME}" 1>&2
		printf "       %s stop\n" "${SCRIPTNAME}" 1>&2
		printf "       %s start-vm VM_NAME\n" "${SCRIPTNAME}" 1>&2
		exit 3
	;;
esac

