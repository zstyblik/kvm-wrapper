#!/bin/sh
#
# Bootstrap VM
# Copyright (C) 2011 Benjamin Cohen <bencoh@codewreck.org>
#                    Dominique Martinet <asmadeus@codewreck.org>
# Published under the WTFPLv2 (see LICENSE)

ARCH=${ARCH:-$(uname -m)}
ARCH_SUFFIX="686"
DPKG_ARCH="i386"

if [ "$ARCH" = "x86_64" ]; then
	ARCH_SUFFIX="amd64"
	DPKG_ARCH="amd64"
fi

### Configuration
BOOTSTRAP_LINUX_IMAGE="linux-image-$ARCH_SUFFIX"
BOOTSTRAP_DEBIAN_MIRROR=${BOOTSTRAP_DEBIAN_MIRROR:-"http://ftp.fr.debian.org/debian/"}
#BOOTSTRAP_FLAVOR=${BOOTSTRAP_FLAVOR:-lenny}
BOOTSTRAP_EXTRA_PKGSS="vim-nox,htop,screen,less,bzip2,bash-completion,locate,\
acpid,acpi-support-base,bind9-host,openssh-server,locales,ntp,busybox,\
$BOOTSTRAP_LINUX_IMAGE"
if [ "$BOOTSTRAP_PARTITION_TYPE" = "msdos" ]; then
	BOOTSTRAP_EXTRA_PKGSS+=",grub"
fi
BOOTSTRAP_CONF_DIR="$BOOTSTRAP_DIR/$BOOTSTRAP_DISTRIB/conf"
BOOTSTRAP_KERNEL="$BOOT_IMAGES_DIR/vmlinuz-$ARCH_SUFFIX"
BOOTSTRAP_INITRD="$BOOT_IMAGES_DIR/initrd.img-$ARCH_SUFFIX"
BOOTSTRAP_CACHE="$CACHE_DIR/$BOOTSTRAP_FLAVOR-$DPKG_ARCH-debootstrap.tar"
###

bs_copy_from_host()
{
	local FILE=${1:-''}
	if [ -z "${FILE}" ]; then
		return 1
	fi
	cp -rf --parents "$FILE" "$MNTDIR/$FILE" || true
} # bs_copy_from_host()

bs_copy_conf_dir()
{
	cp -rf "$BOOTSTRAP_CONF_DIR/"* "$MNTDIR/"
} # bs_copy_conf_dir()

bootstrap_fs()
{

	check_create_dir "$LOGDIR"
	local LOGFILE="$LOGDIR/$VM_NAME-boostrap-$(date +%Y-%m-%d-%H:%M:%S)"

#npipe="/tmp/$$-pipe.tmp"
#CLEANUP+=("rm -f $npipe")
#mknod $npipe p
#tee <$npipe "$LOGFILE" &
#exec 1>&-
#exec 1>$npipe

# well - this or { ... } |tee -a "$LOGFILE" - but you loose environment there,
# so this sucks. gotta cut it in about five pieces and it's ugly :P

	test_file "$BOOTSTRAP_KERNEL" ||\
		fail_exit "Couldn't find bootstrap kernel : $BOOTSTRAP_KERNEL"
	test_file "$BOOTSTRAP_INITRD" ||\
		fail_exit "Couldn't find bootstrap initrd : $BOOTSTRAP_INITRD"

	MNTDIR=$(mktemp -d)
	CLEANUP+=("rmdir $MNTDIR")
	local DISKDEV=${1:-''}
	local PARTDEV=${1:-''}

	local rootdev="LABEL=rootdev"
	local swapdev
	local swapuuid

	if [ "$BOOTSTRAP_PARTITION_TYPE" = "msdos" ]; then
		if [ -n "$SWAP_SIZE" ]; then
			sfdisk -D -H 255 -S 63 -uM --Linux "$DISKDEV" <<EOF
,$ROOT_SIZE,L,*
,,S
EOF
		else
			sfdisk -D -H 255 -S 63 -uM --Linux "$DISKDEV" <<EOF
,,L,*
EOF
		fi # if [ -n "$SWAP_SIZE" ]; then
		PARTDEV=$(map_disk "$DISKDEV")

		if [ -n "$SWAP_SIZE" ]; then
			swapdev=$(printf "%s" "${PARTDEV}" | | \
				awk '{ swapdev=substr($0, 0, length($0)); printf("%s2", swapdev); }')
			swap_uuid=$(mkswap -f "$swapdev" | grep -o -e 'UUID=.*')
		fi # if [ -n "$SWAP_SIZE" ]; then

		CLEANUP+=("unmap_disk $DISKDEV")
	fi # if [ "$BOOTSTRAP_PARTITION_TYPE" = "msdos" ]; then

	mkfs.ext3 -L rootdev "$PARTDEV"

	mount "$PARTDEV" "$MNTDIR"

	CLEANUP+=("umount $MNTDIR")
	CLEANUP+=("sync")

	printf "\n\n"

	# Debootstrap cache
	local DEBOOTSTRAP_CACHE_OPTION=""
	if [ -n "$BOOTSTRAP_CACHE" ]; then
		test_file_rw "$BOOTSTRAP_CACHE" &&\
			find "$BOOTSTRAP_CACHE" -mtime +15 -exec rm {} \;

		if ! test_file_rw "$BOOTSTRAP_CACHE" ; then
			printf \
				"Debootstrap cache either absent or to old : building a new one ...\n"
			eval debootstrap --arch $DPKG_ARCH --make-tarball "$BOOTSTRAP_CACHE" \
				--include="$BOOTSTRAP_EXTRA_PKGSS" "$BOOTSTRAP_FLAVOR" "$MNTDIR" \
				"$BOOTSTRAP_DEBIAN_MIRROR" || true
		fi # if ! test_file_rw "$BOOTSTRAP_CACHE" ; then
		if test_file "$BOOTSTRAP_CACHE"; then
			printf "Using debootstrap cache: %s\n" "$BOOTSTRAP_CACHE"
			DEBOOTSTRAP_CACHE_OPTION="--unpack-tarball \"$BOOTSTRAP_CACHE\""
		else
			printf "Building debootstrap cache failed.\n"
		fi # if test_file "$BOOTSTRAP_CACHE"; then
	fi # if [ -n "$BOOTSTRAP_CACHE" ]; then

	# Now build our destination
	eval debootstrap --arch $DPKG_ARCH "$DEBOOTSTRAP_CACHE_OPTION" \
		--foreign --include="$BOOTSTRAP_EXTRA_PKGSS" "$BOOTSTRAP_FLAVOR" \
		"$MNTDIR" "$BOOTSTRAP_DEBIAN_MIRROR"

	# Fix for linux-image module which isn't handled correctly by debootstrap
	printf "warn_initrd = no\n" > "$MNTDIR/etc/kernel-img.conf"
	printf "do_symlinks = no\n" >> "$MNTDIR/etc/kernel-img.conf"


	# init script to be run on first VM boot
	local BS_FILE="$MNTDIR/bootstrap-init.sh"
	cat > "$BS_FILE" << EOF
#!/bin/sh
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
mount -nt proc proc /proc
mount -no remount,rw /
cat /proc/mounts

/debootstrap/debootstrap --second-stage

printf '\n\n\n'

{
EOF

	if [ "$BOOTSTRAP_PARTITION_TYPE" = "msdos" ]; then
		cat >> "$BS_FILE" << EOF
/usr/sbin/grub-install /dev/[vh]da
sed -i -e 's/#\(GRUB_TERMINAL=console\)/\1/' /etc/default/grub
/usr/sbin/update-grub
EOF
	fi

	if [ -n "$BOOTSTRAP_FIRSTRUN_COMMAND" ]; then
		printf "eval %s\n" "$BOOTSTRAP_FIRSTRUN_COMMAND" >> "$BS_FILE"
	fi

	cat >> "$BS_FILE" << EOF
update-locale
locale-gen
dhclient eth0

aptitude update

echo "Bootstrap ended, halting"
} 2>&1 | /usr/bin/tee -a /var/log/bootstrap.log
exec /sbin/init 0
EOF

	# Used by update-locale/locale-gen in BS_FILE
	bs_copy_from_host /etc/default/locale
	bs_copy_from_host /etc/locale.gen
	bs_copy_from_host /etc/locale.alias

	chmod +x "$BS_FILE"

	if [ -n "$BOOTSTRAP_PRERUN_COMMAND" ]; then
		eval "$BOOTSTRAP_PRERUN_COMMAND"
	fi

	# umount
	sync
	umount "$MNTDIR"

	# Start VM to debootstrap, second stage
	# put vhost_net if supported
	desc_update_setting "KVM_NETWORK_MODEL" "virtio-net-pci"
	test_blockdev "$KVM_DISK1" &&\
		desc_update_setting "KVM_DRIVE_IF" "virtio-blk-pci,scsi=off"
	desc_update_setting "KVM_KERNEL" "$BOOTSTRAP_KERNEL"
	desc_update_setting "KVM_INITRD" "$BOOTSTRAP_INITRD"
	desc_update_setting "KVM_APPEND" "root=$rootdev ro init=/bootstrap-init.sh"


	kvm_init_env "$VM_NAME"


	KVM_MANAGE_DISKS=no kvm_start_vm "$VM_NAME"

	sync
	mount "$PARTDEV" "$MNTDIR"
	sync

	cat "$MNTDIR/var/log/bootstrap.log" >> "$LOGFILE"

	{
		rm "$BS_FILE"

		# Copy some files/configuration from host
		bs_copy_from_host /etc/hosts
		bs_copy_from_host /etc/resolv.conf
		bs_copy_from_host /etc/timezone
		bs_copy_from_host /etc/localtime


		printf "%s\n" "$VM_NAME" > "$MNTDIR/etc/hostname"
		# Custom files
		bs_copy_conf_dir

		# fstab
		cat > "$MNTDIR/etc/fstab" << EOF
# <file system>	<mount point>	<type>	<options>	<dump>	<pass>
$rootdev	/		ext3	errors=remount-ro	0	1
proc		/proc	proc	defaults			0	0
sysfs		/sys	sysfs	defaults			0	0
EOF

		if [ -n "$swap_uuid" ]; then
			printf "%s		none	swap	sw	0	0\n" "$swap_uuid" >> "$MNTDIR/etc/fstab"
		fi


		# interfaces
		local IF_FILE="$MNTDIR/etc/network/interfaces"
		cat > "$IF_FILE" << EOF
auto lo
iface lo inet loopback

auto eth0
EOF
		if [ -n "$BOOTSTRAP_NET_ADDR" ]; then
			cat >> "$IF_FILE" << EOF
iface eth0 inet static
	address $BOOTSTRAP_NET_ADDR
	netmask $BOOTSTRAP_NET_MASK
	network $BOOTSTRAP_NET_NW
	gateway $BOOTSTRAP_NET_GW
EOF
		else
			cat >> "$IF_FILE" << EOF
iface eth0 inet dhcp
EOF
		fi # if [ -n "$BOOTSTRAP_NET_ADDR" ]; then

		# squeeze sucks. no, really, I mean it.
		sed -i -e 's/root:\*:/root::/' "$MNTDIR/etc/shadow"

		sed -i -e "s@DEBIAN_MIRROR@$BOOTSTRAP_DEBIAN_MIRROR@" \
			"$MNTDIR/etc/apt/sources.list"
		sed -i -e "s/FLAVOR/$BOOTSTRAP_FLAVOR/" "$MNTDIR/etc/apt/sources.list"

		# Allow login from serial console
		printf "T0:23:respawn:/sbin/getty -L ttyS0 115200\n" \
			>> "$MNTDIR/etc/inittab"

		if [ "$BOOTSTRAP_PARTITION_TYPE" = "msdos" ]; then
			desc_remove_setting "KVM_KERNEL"
			desc_remove_setting "KVM_INITRD"
			desc_remove_setting "KVM_APPEND"
		else
			desc_update_setting "KVM_APPEND" "root=$rootdev ro"
		fi

		if [ -n "$BOOTSTRAP_FINALIZE_COMMAND" ]; then
			eval "$BOOTSTRAP_FINALIZE_COMMAND"
		fi

		sync

		printf "Bootstrap success '%s'!\n" "${VM_NAME}"
	} 2>&1 | tee -a "$LOGFILE"
} #bootstrap_fs()

