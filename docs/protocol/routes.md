# Subnet routes and host routing

| Fact | Status |
|---|---|
| The approved subnet routes of an advertising node appear in its `AllowedIPs` (`PrimaryRoutes`) in peers' netmaps; after revocation they disappear | Observed (lab/scripts/subnet_setup.sh) |
| The official client installs routes into **table 52**: one /32 per peer plus the subnet routes; policy rule `5270: from all lookup 52` | Observed (ts1 `ip rule` / `ip route show table 52`) |
| The official client uses fwmark `0x80000/0xff0000` (rules 5210/5230/5250) so its own traffic bypasses table 52 | Observed |
| **flowmesh**: routes go into the main table via the TUN (`100.64.0.0/10`, the mesh v6 /48, plus subnet routes); no fwmark is used | Implemented. Interop differential identical (lab/scripts/subnet_diff.sh) |
| **Running on a router**: a router that uses fwmarks for its own policy routing may claim the same bits as the official client (`0x80000/0xff0000`). The routing table and fwmark layout must be chosen together with the router's own marks | Not supported yet |
