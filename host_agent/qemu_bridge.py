import os
import pexpect


class QEMUBridge:
    """
    Host-to-guest serial bridge. Works with both guest trees:
      * RISC-V xv6 (has kernel/riscv.h)  -> `make qemu`, qemu-system-riscv64
      * x86 xv6-public                   -> `make qemu-nox`, qemu-system-i386

    The QEMU binary can be given as qemu_bin=..., or in the QEMU_BIN
    environment variable.
    """

    I386_QEMU = "/home/mahi/Downloads/qemu-master/build/qemu-system-i386"

    def __init__(self, xv6_dir="../xv6-riscv", timeout=20, qemu_bin=None):
        self.xv6_dir = os.path.abspath(xv6_dir)
        if not os.path.isdir(self.xv6_dir):
            raise FileNotFoundError(
                f"xv6 directory not found: {self.xv6_dir} (set XV6_DIR)")
        self.timeout = timeout
        self.is_riscv = os.path.exists(
            os.path.join(self.xv6_dir, "kernel", "riscv.h"))
        default_qemu = "qemu-system-riscv64" if self.is_riscv else self.I386_QEMU
        self.qemu_bin = qemu_bin or os.environ.get("QEMU_BIN") or default_qemu
        self.child = None
        self.start_qemu()

    def start_qemu(self):
        print("[Bridge] Starting QEMU instance in background...")
        target = "qemu" if self.is_riscv else "qemu-nox"
        make_cmd = f"make {target} QEMU={self.qemu_bin}"
        self.child = pexpect.spawn(
            make_cmd,
            cwd=self.xv6_dir,
            encoding="utf-8",
            timeout=max(self.timeout, 120),  # first expect includes the build
        )
        self.child.expect(r"\$ ")
        self.child.timeout = self.timeout
        print("[Bridge] QEMU initialized and ready at shell prompt.")

    def send_command(self, command: str, timeout=None) -> str:
        if not self.child or not self.child.isalive():
            raise RuntimeError("QEMU process is not running.")
        try:
            self.child.sendline(command)
            self.child.expect(r"\$ ", timeout=timeout or self.timeout)
            raw_output = self.child.before
            cleaned = [ln for ln in raw_output.splitlines()
                       if ln.strip() != command.strip()]
            return "\n".join(cleaned).strip()
        except pexpect.TIMEOUT:
            return "Error: QEMU command timed out."
        except pexpect.EOF:
            return "Error: QEMU process terminated unexpectedly."

    def close(self):
        if self.child and self.child.isalive():
            self.child.send("\x01x")  # Ctrl+A then x quits QEMU
            self.child.close()
            print("[Bridge] QEMU session closed.")
