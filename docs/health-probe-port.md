# Health probe port reservation

The daemon keeps its loopback health probe at `127.0.0.1:39400`. Because
39400 is in the usual ephemeral source-port range, the DaemonSet mounts the
host's `/proc/sys/net/ipv4/ip_local_reserved_ports` and passes it through
`--reserved-ports-path`. Before creating the controller-runtime manager, the
privileged host-network daemon adds its probe port to that sysctl. Existing
individual ports and ranges are preserved, and an existing reservation is
left unchanged. Failure to read or update the reservation stops startup with
an error rather than silently leaving the port unprotected.

The reservation remains when the Pod stops; it is not removed on shutdown
because doing so would reopen the collision window during upgrades and
restarts. The Host Port Registry should also record 39400 as INF's loopback
health probe port. Registry entries and containerPort declarations do not
themselves reserve ports in the kernel.

## Initial installation and node reboot

This startup reservation prevents subsequent automatic allocations. It does
not evict connections already using 39400, or prevent a process from explicitly
binding that port. A connection established before the daemon first runs can
still delay recovery until that connection closes. The reservation is reapplied
when the daemon starts after reboot, but the interval before it starts remains
unprotected.

To exclude that boot-time interval too, provision a persistent node reservation
before host-network workloads start, using the platform's node configuration
mechanism. Include 39400 in the node's managed `net.ipv4.ip_local_reserved_ports`
value, preserving all other required ports. Coordinate changes with other
sysctl writers: Linux replaces the entire list on each write, so concurrent
read/modify/write operations are not atomic and later configuration must retain
the INF reservation. Pod securityContext net.* sysctls cannot configure this
for a host-network Pod.

An optional OpenShift MachineConfig example is provided in
[`config/samples/39400-reservation-machineconfig.yaml`](../config/samples/39400-reservation-machineconfig.yaml).
It adds a boot service after systemd-sysctl and before network-pre/kubelet,
merging 39400 into the effective list. Adjust its role label for every
MachineConfigPool hosting INF, review ordering against any custom early network
services, and plan the node rollout. The operator does not automatically apply
this cluster-scoped configuration. Other runtime sysctl writers must still
preserve the reservation.

## Verification

On a test node, record the existing reserved-port list, start the updated
daemon, and check that the list contains 39400 (possibly inside a range) and
all prior reservations. Confirm a listener on `127.0.0.1:39400` and that the
daemon is Ready. Restart the daemon and confirm the reservation remains without
duplicates. Test a reboot separately when validating persistent node configuration.

For the original failure, create a localhost connection with local port 39400
before starting INF. Confirm the daemon reserves 39400, then release the
connection and confirm the daemon recovers on restart. Do not terminate unrelated
host-network workloads automatically to free the port.
