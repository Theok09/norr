# systemd

Suggested hardening:
- `Restart=on-failure`
- `NoNewPrivileges=true` where compatible
- minimized capabilities
- private temporary storage
- explicit resource limits
- controlled log destination

Do not blindly enable hardening options that prevent TUN or socket operation; validate each unit on target kernels.
