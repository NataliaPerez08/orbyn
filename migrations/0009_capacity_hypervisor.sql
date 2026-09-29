-- Phase 2 inventory enrichment: virtualization metadata.
-- Canonical hypervisor id detected by the host collectors
-- (kvm, vmware, virtualbox, hyperv, xen, lxc, docker, podman,
-- systemd-nspawn, wsl, bhyve, bochs, uml, unknown); NULL means no
-- virtualization evidence was found (bare metal).

ALTER TABLE asset_capacity ADD COLUMN hypervisor TEXT;
