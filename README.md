# WIP Kernel 4.15.*
WIP Patched Kernel Sources (Linux 4.15.4)

 - Full kernel adaptation to version Ubuntu 18.04 LTS Bionic.

 - Full kernel adaptation to build GCC7/GCC8.

## Full support:
 
 - Indirect Branch Restricted Speculation (IBRS)
 - Indirect Branch Prediction Barrier (IBPB)


## Add Linux Kernel Runtime Guard (LKRG)

 Linux Kernel Runtime Guard (LKRG) is a loadable kernel module that
performs runtime integrity checking of the Linux kernel and detection of
security vulnerability exploits against the kernel.


## Important security fix:

Current status of this kernel for the Spectre and Meltdown vulnerabilities
--------------------------------------------------------------------------

Spectre and Meltdown mitigation detection tool

Checking for vulnerabilities on current system

Hardware check
* Hardware support (CPU microcode) for mitigation techniques
  * Indirect Branch Restricted Speculation (IBRS)
    * SPEC_CTRL MSR is available:  YES 
    * CPU indicates IBRS capability:  YES  (SPEC_CTRL feature bit)
    * Kernel has set the spec_ctrl flag in cpuinfo:  NO 
  * Indirect Branch Prediction Barrier (IBPB)
    * PRED_CMD MSR is available:  YES
    * CPU indicates IBPB capability:  YES  (SPEC_CTRL feature bit)
  * Single Thread Indirect Branch Predictors (STIBP)
    * SPEC_CTRL MSR is available:  YES
    * CPU indicates STIBP capability:  YES
  * Enhanced IBRS (IBRS_ALL)
    * CPU indicates ARCH_CAPABILITIES MSR availability:  NO
    * ARCH_CAPABILITIES MSR advertises IBRS_ALL capability:  NO
  * CPU explicitly indicates not being vulnerable to Meltdown (RDCL_NO):  NO
  * CPU microcode is known to cause stability problems:
  YES  (model 71 stepping 1 ucode 0x1b)


* CPU vulnerability to the three speculative execution attacks variants
  * Vulnerable to Variant 1:  YES (Enable Mitigation: __user pointer sanitization)
  * Vulnerable to Variant 2:  YES (Enable Mitigation: PTI)
  * Vulnerable to Variant 3:  YES (Enable Mitigation: Full generic retpoline, IBPB, IBRS_FW)

CVE-2017-5753 [bounds check bypass] aka 'Spectre Variant 1'
* Mitigated according to the /sys interface:
  YES  (kernel confirms that the mitigation is active)
* Kernel has array_index_mask_nospec:
  YES  (1 occurence(s) found of 64 bits array_index_mask_nospec())
* Checking count of LFENCE instructions following a jump in kernel:
  YES  (1839 jump-then-lfence instructions found, which is >= 30 (heuristic))
#### STATUS:  NOT VULNERABLE  (Mitigation: __user pointer sanitization)

CVE-2017-5715 [branch target injection] aka 'Spectre Variant 2'
* Mitigated according to the /sys interface:
  YES  (kernel confirms that the mitigation is active)
* Mitigation 1
  * Kernel is compiled with IBRS/IBPB support:  YES
  * Currently enabled features
    * IBRS enabled for Kernel space:  NO
    * IBRS enabled for User space:  NO
    * IBPB enabled:  YES
* Mitigation 2
  * Kernel compiled with retpoline option:  YES
  * Kernel compiled with a retpoline-aware compiler:
  YES  (kernel reports full retpoline compilation)
  * Retpoline enabled:  YES
#### STATUS:  NOT VULNERABLE  (Mitigation: Full generic retpoline, IBPB, IBRS_FW)

CVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'
* Mitigated according to the /sys interface:
  YES  (kernel confirms that the mitigation is active)
* Kernel supports Page Table Isolation (PTI):  YES
* PTI enabled and active:  YES
* Performance impact if PTI is enabled
  * CPU supports PCID:
  YES  (performance degradation with PTI will be limited)
  * CPU supports INVPCID:
  YES  (performance degradation with PTI will be limited)
* Running as a Xen PV DomU:  NO
#### STATUS:  NOT VULNERABLE  (Mitigation: PTI)



```bash
 This is a mainline Linux kernel distribution with custom settings.
Optimized to take full advantage of high-performance.

Supports all recent 64-bit versions of Debian and Ubuntu-based systems. 

Main Features:

Tuned CPU for Intel i5/i7/Atom platform.
PDS CPU Scheduler & Multi-Queue I/O Block Layer w/ BFQ-MQ for smoothness and responsiveness.
Caching, Virtual Memory Manager and CPU Governor Improvements.
General-purpose Multitasking Kernel.
Built on the latest GCC 7.3 or (GCC 8)
DRM Optimized Performance.
BBR TCP Congestion Control.
Intel CPUFreq (P-State passive mode).
ZFS, AUFS, BFQ and Ureadahead support available.
Linux Kernel Runtime Guard (LKRG)
```

### Kernel config file

```bash
 Kernel config file locate to directory
 debian.master/config/amd64/config.flavour.generic
```

## Download and install kernel from my build (DEB packages):

BUILDBOX automatically builds the packages. Look at the file date and the build number.

[Download packages](https://drive.google.com/drive/folders/1qK8FYHb1Dy7nHJZstm1zfno2Y8MEy2wG)

[Read this before installing](https://github.com/AndyLavr/wip-kernel/releases)


### Recommended system configuration


# Config files

- /etc/default/grub

```bash
GRUB_CMDLINE_LINUX_DEFAULT="spectre_v2=auto ipv6.disable=1 intremap=no_x2apic_optout acpi_osi=Linux acpi_backlight=vendor intel_iommu=on swiotlb=32768 apparmor=0"
GRUB_CMDLINE_LINUX="systemd.gpt_auto=0"
```

- /etc/sysctl.conf

```bash
vm.laptop_mode=0
vm.swappiness=60
vm.vfs_cache_pressure=1000
vm.dirty_writeback_centisecs=15000

# You can monitor the kernel behavior with regard to the dirty
# pages by using grep -A 1 dirty /proc/vmstat
vm.dirty_background_ratio=5
vm.dirty_ratio=15

# required free memory (set to 1% of physical ram)
vm.min_free_kbytes=328979

# system open file limit
fs.file-max=2055936

# Core dump suidsafe
kernel.core_uses_pid = 1
kernel.core_pattern = /tmp/core-%e-%s-%u-%g-%p-%t
fs.suid_dumpable = 2

kernel.printk=4 4 1 7
kernel.core_uses_pid=1
kernel.sysrq=0

# VMware
kernel.shmmax=30318719385
kernel.shmmni = 16384

### ---

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 1800
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_mem = 50576   64768   98152
net.ipv4.tcp_orphan_retries = 0
net.ipv4.tcp_syncookies = 1
net.netfilter.nf_conntrack_max = 16777216
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.route.flush = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.lo.rp_filter = 1
net.ipv4.conf.enp4s0.rp_filter = 1
net.ipv4.conf.wlp5s0.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.lo.accept_source_route = 0
net.ipv4.conf.enp4s0.accept_source_route = 0
net.ipv4.conf.wlp5s0.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ip_forward = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.core.somaxconn = 65535
fs.inotify.max_user_watches = 16777216
#
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.ip_default_ttl = 63
#
net.ipv4.tcp_ecn = 1
net.core.default_qdisc = fq_codel
#
net.ipv4.tcp_fastopen = 3
#
# Lowlatency Kernel Tuning
kernel.perf_cpu_time_max_percent=100
#
# IO shedulers
vm.dirty_background_bytes=67108864
vm.dirty_bytes=134217728
#
# Huge Page
vm.nr_hugepages=4096
vm.nr_overcommit_hugepages=4096
vm.hugetlb_shm_group=1001
#
# Test
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.netdev_max_backlog = 16384
#
net.ipv4.tcp_rmem = 8192 87380 33554432
net.ipv4.tcp_wmem = 8192 65536 33554432
#
#
kernel.yama.ptrace_scope=2
```

- /etc/network/interfaces

```bash
wireless-power off
```

- /etc/NetworkManager/conf.d/default-wifi-powersave-on.conf

```bash
[connection]
wifi.powersave = 2
```


## Installation Linux Kernel Runtime Guard (LKRG):

 Installation of LKRG is exactly the same as loading normal kernel
module. As soon as system is installed it starts the work. If default
logging level is used, LKRG produces one short sentence saying that
system is clean unless corruptions are detected.
```bash
$ modprobe lkrg

$ modinfo lkrg
filename:       /lib/modules/4.15.4-wip-x20-broadwell/kernel/drivers/staging/lkrg/lkrg.ko
license:        GPL v2
description:    pi3's Linux kernel Runtime Guard
author:         Adam 'pi3' Zabrocki (http://pi3.com.pl)
srcversion:     FDD572FB762135ED20D6EC2
depends:
staging:        Y
retpoline:      Y
intree:         Y
name:           lkrg
vermagic:       4.15.4-wip-x20-broadwell SMP mod_unload modversions retpoline
signat:         PKCS#7
signer:
sig_key:
sig_hashalgo:   md4
parm:           p_init_log_level:Logging level init value [1 (alive) is default] (uint)


 Add file /etc/modprobe.d/lkrg.conf

and insert string options:

options lkrg p_init_log_level=3
```

 The project has built in a sysctl interface which enables the
interaction between the administrator and LKRG. By default 5 different
options are available:
```bash
 # sysctl -a|grep lkrg
 lkrg.block_modules = 0
 lkrg.clean_message = 1
 lkrg.force_run = 0
 lkrg.hide = 0
 lkrg.log_level = 3
 lkrg.timestamp = 15
```


## Fix ATH10k WiFi work

```
Add to /etc/modprobe.d file ath10k_core.conf and add string:

 options ath10k_core skip_otp=y

Create a symbolic link from firmware files:

Example for (Qualcomm Atheros QCA6174 802.11ac Wireless Network Adapter)

ln -s /lib/firmware/ath10k/QCA6174/hw2.1/board.bin /lib/firmware/ath10k/pre-cal-pci-0000:05:00.0.bin

ln -s /lib/firmware/ath10k/QCA6174/hw2.1/board-2.bin /lib/firmware/ath10k/cal-pci-0000:05:00.0.bin
```


## Fix start X session

```bash
If start X session fail and error from system journal :

lightdm[1182]: PAM unable to dlopen(pam_kwallet.so): 
/lib/security/pam_kwallet.so: cannot open shared object file: No such file or directory

then turn off all the lines containing pam_kwallet.co and pam_kwallet5.so in
all the files in this directory /etc/pam.d
```

# Intel – Fix MMC/GPT warning.

```bash

 I had been getting a warning on boot with recent kernels on my 
Intel based UP system, and found a workaround.
The error flagged is – apparently – harmless, and is due to systemd
not being able to recognise some mmc disk partitions at that stage of the boot process.

......
[ 5.124250] systemd-gpt-auto-generator[416]: Failed to dissect: Input/output error
......

The workaround is to add systemd.gpt_auto=0 to the kernel command line.

```
