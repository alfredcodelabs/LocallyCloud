# Supported platforms

LocallyCloud is a Linux program. It is developed natively on Arch Linux and distributed as an
Arch package and as one `.deb` for Debian, Ubuntu LTS, and their derivatives, including WSL 2.
On macOS and on Windows without WSL, run it inside a Linux virtual machine and use it from the
host through a forwarded port.

## Support levels

| Level | Platform | Architectures | How to install |
| --- | --- | --- | --- |
| Tier 1 | Arch Linux (current) | x86_64 | Arch package (`pacman -U`) or build from source |
| Tier 2 | Debian 13 | amd64, arm64 | `.deb` with `apt` |
| Tier 2 | Ubuntu 24.04 LTS and 26.04 LTS | amd64, arm64 | `.deb` with `apt` |
| Tier 2 | Distributions based on the releases above (Linux Mint, Pop!_OS, elementary OS, …) | amd64, arm64 | `.deb` with `apt` |
| Tier 2 | Windows 10/11 with WSL 2 running one of the releases above | amd64, arm64 | `.deb` with `apt` inside WSL |
| Best effort | Arch Linux ARM | aarch64 | `makepkg` with `packaging/arch/PKGBUILD` |
| Best effort | Other Linux distributions with glibc 2.39 or later (Fedora, openSUSE Tumbleweed, …) | x86_64, aarch64 | Build from source or [user-only installation](../README.md#user-only-installation-without-sudo) |
| Through a VM | macOS (Intel and Apple Silicon), Windows without WSL | — | [Linux VM with a forwarded port](#macos-and-windows-without-wsl) |
| Not supported | Native Windows or macOS, glibc older than 2.39 (Ubuntu 22.04, Debian 12), 32-bit systems | — | — |

- **Tier 1:** the development platform. Every change is built and tested here first; CI builds and
  installs the package.
- **Tier 2:** CI builds the `.deb` for each architecture and installs it with `apt` on Debian 13,
  Ubuntu 24.04, and Ubuntu 26.04, then starts the server. Releases wait for those checks.
- **Best effort:** expected to work and accepted bug reports, but not built or tested by CI.

The `.deb` requires glibc 2.39 or later. On older releases `apt` refuses to install it instead of
installing a binary that cannot start.

## What each feature needs

All in-process services (S3, DynamoDB, SQS, SNS, EventBridge, Step Functions, IAM, KMS, SSM,
CloudWatch, API Gateway, and others) work on every supported platform with no extra software.
Some features need host components:

| Feature | Requirement | Notes |
| --- | --- | --- |
| Lambda, ECS/Fargate, EC2 (OCI) | `crun` or `youki`, a systemd user session with a user D-Bus, delegated cgroup v2 memory control | The `.deb` recommends `dbus-user-session`. On WSL 2, enable systemd (below). |
| Lambda, ECS, EC2 (Firecracker) | Read and write access to `/dev/kvm` | Used automatically when available; otherwise OCI. Inside a VM, needs nested virtualization. |
| ZIP Lambda functions | The matching interpreter on the host (`python3.x`, `node`) | Use what your distribution ships; for example Debian 13 has Python 3.13 and Node.js 20. |
| Custom runtimes (`provided.al2023`) | A binary built for the host architecture | An x86_64 binary does not run on an arm64 host, and vice versa. |
| RDS and RDS Data API | PostgreSQL 16 or later | Use the newest version your distribution provides. Found on `PATH` or under `/usr/lib/postgresql/<version>/bin`; `LOCALLYCLOUD_PG_BIN_DIR` overrides it. |
| Dashboard from the applications menu | `xdg-utils` | The dashboard URL works in any browser without it. |

## WSL 2

Install a supported Ubuntu or Debian distribution in WSL 2 and the `.deb` with `apt`, as on any
other Tier 2 system. To run Lambda, ECS, or EC2, enable systemd so that a user session and D-Bus
exist. In the distribution, add to `/etc/wsl.conf`:

```ini
[boot]
systemd=true
```

Then run `wsl --shutdown` from Windows and reopen the distribution. WSL 2 forwards `localhost` to
Windows, so tools on Windows can use `http://127.0.0.1:4566` directly.

## macOS and Windows without WSL

Run LocallyCloud in a Linux virtual machine and use it from the host:

1. Create a VM with a Tier 2 distribution, for example Ubuntu 24.04 or Debian 13. Use the arm64
   image on Apple Silicon and the amd64 image on Intel. Any hypervisor works: QEMU, UTM,
   VirtualBox, Parallels, VMware, or Hyper-V.
2. Install the `.deb` in the VM with `apt` and start `locallycloud` as a regular user.
3. Forward the VM's port 4566 to port 4566 on the host's loopback interface. With QEMU user
   networking:

   ```sh
   -nic user,hostfwd=tcp:127.0.0.1:4566-:4566
   ```

   UTM, VirtualBox, and Parallels offer the same setting as a port-forwarding rule. Inside the VM,
   start LocallyCloud with `LOCALLYCLOUD_HOST=0.0.0.0` so that it accepts the forwarded
   connection; the forward itself only listens on the host's loopback.
4. On the host, use `http://127.0.0.1:4566` as the endpoint, exactly as on Linux. The AWS CLI
   profile, SDKs, Terraform, and SAM need no other change, and the dashboard is at
   `http://127.0.0.1:4566/_locallycloud/ui`.

Prefer the loopback forward over connecting to the VM's network address. With a bridged or
host-only address, any machine that can reach that network can use the emulator with the
well-known `test` credentials. If you must use the VM's address anyway, restrict it with the VM's
firewall.

Presigned S3 URLs are signed by the client SDK for the endpoint the client uses, so they work
through the forward. Do not set `LOCALLYCLOUD_ENDPOINT_URL` (or `AWS_ENDPOINT_URL`) in the VM to
the host's address: that variable is the endpoint Lambda, ECS, and EC2 guests inside the VM use
to call back into the emulator, and the default already points to the VM itself.

Run x86_64 workloads, such as an x86_64 `provided.al2023` Lambda binary, in an amd64 VM on an
Intel host. Emulating amd64 on Apple Silicon works but is much slower.
