#!/bin/sh
# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
#
# Collect the host-side evidence fabricrca needs from a Linux host (read-only).
#   ./collect_host_info.sh  > host_info.json
#   multipath -ll           > multipath_ll.txt
#   journalctl -k -u multipathd --since "-2h" -o short-iso > host.log
#
# host_info.json maps SCSI hosts to initiator WWNs and H:C:T to target WWNs,
# using the standard sysfs FC transport classes.
set -eu

printf '{\n  "hba_map": {'
sep=""
for h in /sys/class/fc_host/host*; do
  [ -e "$h/port_name" ] || continue
  printf '%s\n    "%s": "%s"' "$sep" "$(basename "$h")" "$(cat "$h/port_name")"
  sep=","
done
printf '\n  },\n  "target_map": {'
sep=""
for t in /sys/class/fc_transport/target*; do
  [ -e "$t/port_name" ] || continue
  hct=$(basename "$t" | sed 's/^target//')
  printf '%s\n    "%s": "%s"' "$sep" "$hct" "$(cat "$t/port_name")"
  sep=","
done
printf '\n  }\n}\n'
