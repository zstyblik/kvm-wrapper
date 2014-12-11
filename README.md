# kvm-wrapper

This is a forked version of http://codewreck.org/kvm-wrapper/. You should visit
that site regardless you want this version or original to show those guys some
love. Also, kvm-wrapper features are listed there ;-)

## What's this good for?

It should make virtualization and QEMU instrumentation easier. Especially when
you can't or don't want to use VMware or VirtualBox or libvirt etc. Despite
clustering and init scripts are provided, personally, I don't use kvm-wrapper
beyond workstation and for testing. However, kvm-wrapper is being sucessfully
used in production.

## Wait, what?

Actually, none of VMware/VirtualBox/libvirt would get things done for me. Not
in easy way anyway. Also, VMware Workstation is paid for.

## What's the diff?

* primary objective was less Bash and more portability
* secondary objective to add support for VDE2 and later openvswitch
* and be able to pass parameters to VDE2 and openvswitch, so I could setup VLANs

## Requirements

Requirements should be the same as in original version:

* qemu
* bash(probably and still)
* dtach or GNU screen
* lvm2 tools
* kpartx for debootstrap

Of course, if you want to use VDE2 and/or openvswitch, then you will need those.

## Documentation

TODO

## How to contribute

PRs are welcome. However, you should consider whether you want to use original
or this one, though.
