# Subnet routes and host routing

| Fact | Status |
|---|---|
| The approved subnet routes of an advertising node appear in its `AllowedIPs` (`PrimaryRoutes`) in peers' netmaps; after revocation they disappear | Observed (lab/scripts/subnet_setup.sh) |
| The official client installs routes into **table 52**: one /32 per peer plus the subnet routes; policy rule `5270: from all lookup 52` | Observed (ts1 `ip rule` / `ip route show table 52`) |
| The official client uses fwmark `0x80000/0xff0000` (rules 5210/5230/5250) so its own traffic bypasses table 52 | Observed |
| **flowmesh (M6)**: routes go into the main table via the TUN (`100.64.0.0/10`, the mesh v6 /48, plus subnet routes); no fwmark is used | Implemented. Interop differential identical (lab/scripts/subnet_diff.sh) |
| **To do in v3 (CPE takeover)**: the WanFlow gateway agent reserves fwmark bits `0x80000/0xff0000` for the mesh (`pkg/network/marks.go`), and the CPE has its own PBR. The routing table / fwmark layout must be designed together with the agent to avoid conflicts with multi-WAN and acceleration marks | Pending (v3) |
