from engine.core import rule, ev
from ._helpers import one


@rule(id="KRN-001", title="Core exploit mitigations disabled", category="weakness", severity="high",
      confidence="high",
      why="ASLR, KASLR and CPU-vulnerability mitigations make memory-corruption exploits harder. Disabling them is rarely intentional on a desktop.",
      fix="Set kernel.randomize_va_space=2 in /etc/sysctl.d/ and remove mitigations=off / nokaslr / nopti / nospectre_v2 / norandmaps from the kernel command line (bootloader config).",
      requires={"kernel": ["sysctl", "cmdline"]})
def krn_001(ctx):
    d = ctx.d("kernel")
    v = d["sysctl"].get("kernel.randomize_va_space")
    if v is None:
        ctx.partial("kernel.randomize_va_space not readable")
    elif v != 2:
        ctx.fail("kernel.randomize_va_space", [ev("kernel", "sysctl.kernel.randomize_va_space", v, 2)])
    params = (d["cmdline"] or {}).get("params") or {}
    if str(one(params.get("mitigations", ""))).startswith("off"):
        ctx.fail("cmdline: mitigations=off", [ev("kernel", "cmdline.params.mitigations", one(params["mitigations"]), "unset")])
    for k in ctx.th("dangerous_cmdline_params"):
        if k in params:
            ctx.fail(f"cmdline: {k}", [ev("kernel", f"cmdline.params.{k}", True, "unset")])


@rule(id="KRN-002", title="Hardening sysctl is weak", category="weakness", severity="medium", confidence="high",
      why="These kernel settings limit ptrace, unprivileged BPF, link-based file attacks, ICMP redirects and kernel pointer leaks. Weak values make privilege escalation and local attacks easier.",
      fix="Set the recommended value in /etc/sysctl.d/99-hardening.conf and run sysctl --system. Check that nothing you use (debuggers, VPNs) depends on the weak value.",
      requires={"kernel": ["sysctl"]})
def krn_002(ctx):
    sysctl, weak = ctx.d("kernel")["sysctl"], ctx.th("weak_sysctls")
    absent = 0
    for key, bad in weak.items():
        v = sysctl.get(key)
        if v is None:
            absent += 1
        elif v == bad:
            ctx.fail(key, [ev("kernel", f"sysctl.{key}", v, f"not {bad}")])
    if absent == len(weak):
        ctx.partial("none of the hardening sysctl keys could be read")


@rule(id="KRN-003", title="Kernel patch state: old kernel running or CPU vulnerable", category="hygiene",
      severity="medium", confidence="high",
      why="After a kernel upgrade the old kernel keeps running until reboot, so its fixes are not active. CPU vulnerability entries marked 'Vulnerable' mean no mitigation is in place.",
      fix="Reboot into the installed kernel. For 'Vulnerable' CPU entries, update the kernel and the CPU microcode package (intel-ucode or amd-ucode) and reboot.",
      requires={"kernel": ["reboot_check", "cpu_mitigations"]})
def krn_003(ctx):
    d = ctx.d("kernel")
    on_disk = d["reboot_check"].get("running_kernel_modules_on_disk")
    if on_disk is None:
        ctx.partial("could not determine whether the running kernel's modules are on disk")
    elif on_disk is False:
        ctx.fail("running-kernel", [ev("kernel", "reboot_check", f"running {d['reboot_check'].get('running_release')}, its modules are gone from /usr/lib/modules",
                                       "running kernel matches an installed kernel")])
    for name, status in d["cpu_mitigations"].items():
        if isinstance(status, str) and status.startswith("Vulnerable"):
            ctx.fail(f"cpu: {name}", [ev("kernel", f"cpu_mitigations.{name}", status, "Mitigation or Not affected")])
