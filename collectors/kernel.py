#!/usr/bin/env python3
"""Kernel collector (Arch Linux first). FACTS only.

  version/cmdline   uname, /proc/cmdline parsed into params (mitigations=off, nokaslr, init=...)
  sysctl            security-relevant /proc/sys values (None = key absent on this kernel)
  taint             /proc/sys/kernel/tainted decoded (proprietary/out-of-tree/unsigned modules...)
  modules           loaded modules (lsmod) + /etc/modprobe.d blacklist/install overrides + modules-load.d
  mitigations       /sys/devices/system/cpu/vulnerabilities/* (Meltdown, Spectre, ...)
  mac_lockdown      LSM list, AppArmor/SELinux state, kernel lockdown, Secure Boot
  reboot_needed     is the running kernel's module tree still on disk? (classic Arch post-upgrade state)

Usage: sudo python -m collectors.kernel --out kernel.json --pretty
"""
import argparse
import glob
import os
import re

from .common import new_result, read_lines, file_meta, emit

SYSCTLS = [
    "kernel.randomize_va_space", "kernel.kptr_restrict", "kernel.dmesg_restrict",
    "kernel.yama.ptrace_scope", "kernel.unprivileged_bpf_disabled", "net.core.bpf_jit_harden",
    "kernel.kexec_load_disabled", "kernel.sysrq", "kernel.perf_event_paranoid",
    "kernel.unprivileged_userns_clone", "user.max_user_namespaces", "kernel.modules_disabled",
    "kernel.core_pattern", "kernel.core_uses_pid", "kernel.panic_on_oops",
    "fs.protected_hardlinks", "fs.protected_symlinks", "fs.protected_fifos", "fs.protected_regular",
    "fs.suid_dumpable", "vm.mmap_min_addr", "vm.unprivileged_userfaultfd", "dev.tty.ldisc_autoload",
    "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding",
    "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects",
    "net.ipv6.conf.all.accept_redirects", "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.all.accept_source_route", "net.ipv6.conf.all.accept_source_route",
    "net.ipv4.conf.all.log_martians", "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.tcp_syncookies", "net.ipv6.conf.all.accept_ra", "net.ipv4.tcp_timestamps",
]
TAINT_FLAGS = {0: "P proprietary module", 1: "F forced module load", 2: "S SMP-unsafe", 3: "R forced unload",
               4: "M machine check", 5: "B bad page", 6: "U userspace-set", 7: "D kernel died/oops",
               8: "A ACPI table override", 9: "W warning", 10: "C staging driver", 11: "I firmware workaround",
               12: "O out-of-tree module", 13: "E unsigned module", 14: "L soft lockup", 15: "K livepatched",
               16: "X auxiliary", 17: "T struct randomization"}


def read_one(path: str):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return None


def sysctl_value(key: str):
    v = read_one("/proc/sys/" + key.replace(".", "/"))
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return v


def parse_cmdline(text: str) -> dict:
    params: dict = {}
    for tok in text.split():
        k, sep, v = tok.partition("=")
        if k in params:
            if not isinstance(params[k], list):
                params[k] = [params[k]]
            params[k].append(v if sep else True)
        else:
            params[k] = v if sep else True
    return params


def decode_taint(val: int) -> list[str]:
    return [name for bit, name in TAINT_FLAGS.items() if val & (1 << bit)]


def parse_modprobe(lines: list[str]) -> dict:
    blacklist, install = set(), {}
    for l in lines:
        p = l.split("#", 1)[0].split()
        if len(p) >= 2 and p[0] == "blacklist":
            blacklist.add(p[1])
        elif len(p) >= 3 and p[0] == "install":
            install[p[1]] = " ".join(p[2:])[:200]
    return {"blacklist": blacklist, "install": install}


def collect(result=None) -> dict:
    result = result or new_result("kernel")
    uname = os.uname()
    release = uname.release
    data = {"release": release, "version": uname.version, "machine": uname.machine}

    cmd = read_one("/proc/cmdline") or ""
    data["cmdline"] = {"raw": cmd, "params": parse_cmdline(cmd)}
    data["sysctl"] = {k: sysctl_value(k) for k in SYSCTLS}
    sysctl_files = sorted(glob.glob("/etc/sysctl.d/*.conf") + glob.glob("/usr/lib/sysctl.d/*.conf")
                          + (["/etc/sysctl.conf"] if os.path.exists("/etc/sysctl.conf") else []))
    data["sysctl_config_files"] = sysctl_files

    t = sysctl_value("kernel.tainted")
    data["taint"] = {"value": t, "flags": decode_taint(t) if isinstance(t, int) else None}

    mods = []
    for line in read_lines("/proc/modules", result):
        f = line.split()
        if len(f) >= 4:
            mods.append({"name": f[0], "size": int(f[1]), "refcount": int(f[2]),
                         "used_by": [] if f[3] == "-" else [m for m in f[3].split(",") if m]})
    mp_lines = []
    for p in sorted(glob.glob("/etc/modprobe.d/*.conf") + glob.glob("/usr/lib/modprobe.d/*.conf")):
        mp_lines += read_lines(p, result)
    mp = parse_modprobe(mp_lines)
    autoload = []
    for p in sorted(glob.glob("/etc/modules-load.d/*.conf") + glob.glob("/usr/lib/modules-load.d/*.conf")):
        autoload += [l.strip() for l in read_lines(p, result) if l.strip() and not l.startswith(("#", ";"))]
    data["modules"] = {
        "loaded": mods, "loaded_count": len(mods),
        "blacklisted": sorted(mp["blacklist"]), "install_overrides": mp["install"],
        "autoload": sorted(set(autoload)),
        "modules_disabled": data["sysctl"].get("kernel.modules_disabled"),
    }

    vuln = {}
    for p in sorted(glob.glob("/sys/devices/system/cpu/vulnerabilities/*")):
        vuln[os.path.basename(p)] = read_one(p)
    data["cpu_mitigations"] = vuln

    sb = None
    for p in glob.glob("/sys/firmware/efi/efivars/SecureBoot-*"):
        try:
            with open(p, "rb") as f:
                sb = f.read()[-1] == 1
        except OSError:
            pass
    lsm = read_one("/sys/kernel/security/lsm")
    lockdown = read_one("/sys/kernel/security/lockdown")
    sel = read_one("/sys/fs/selinux/enforce")
    data["mac_lockdown"] = {
        "lsm_list": lsm.split(",") if lsm else None,
        "apparmor_enabled": read_one("/sys/module/apparmor/parameters/enabled"),
        "selinux_enforce": {"1": "enforcing", "0": "permissive"}.get(sel) if sel is not None else None,
        "lockdown": (re.search(r"\[(\w+)\]", lockdown).group(1) if lockdown and re.search(r"\[(\w+)\]", lockdown) else lockdown),
        "uefi_boot": os.path.isdir("/sys/firmware/efi"),
        "secure_boot": sb,
    }

    avail = sorted(os.listdir("/usr/lib/modules")) if os.path.isdir("/usr/lib/modules") else None
    data["reboot_check"] = {
        "running_release": release,
        "installed_module_trees": avail,
        "running_kernel_modules_on_disk": (release in avail) if avail is not None else None,
        "note": "False after a kernel upgrade means you are running an old kernel: reboot.",
    }
    data["boot_files_meta"] = [m for m in map(file_meta, ["/boot", "/boot/grub/grub.cfg", "/boot/loader/loader.conf"]) if m.get("exists")]
    result["data"] = data
    return result


def main():
    ap = argparse.ArgumentParser(description="Collect kernel facts (no judgments).")
    ap.add_argument("--out"); ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    emit(collect(), a.out, a.pretty)


if __name__ == "__main__":
    main()
