# Black-box observation captures

Each subdirectory holds one capture session, with a `manifest.json` that records the versions used, the time, and the conclusions.
The baseline captures are produced by `lab/scripts/capture.sh` and redacted with `lab/scripts/redact.py` at generation time: private keys and pre-auth keys are replaced with `<redacted>`, and the remaining keys are only valid in the lab.

These captures are the sources for the protocol facts in `docs/protocol/`, cited as `OBS-<directory name>/<file name>`.

Note: `*-netmap.json`, `*-prefs.json` and `*-status.json` are the official client's **internal view**, not the wire format.
Wire-format captures are recorded as raw messages by the flowmesh probe.
