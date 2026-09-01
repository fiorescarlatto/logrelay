# systemd service

Run logrelay as a persistent service that follows log files and relays them
to your rsyslog/syslog host.

## Files

* `logrelay.sh` - the service script; **this is the file you configure**
  (CONFIG section at the top: destination host/port/proto, log files,
  facility/severity, per-file appnames, extra `logrelay.py` flags).
* `logrelay.service` - the systemd unit; only `ExecStart=` may need a path
  adjustment if you do not deploy to `/opt/logrelay`.

## Install (system service, root)

1. Transfer the repo to the target machine, e.g. `scp -r` it to `~/logrelay`,
   then move it into place. Make sure the `.sh` file keeps Unix line endings
   and the execute bit (transferring from Windows often strips both):

   ```bash
   sudo mv ~/logrelay /opt/logrelay
   sudo chmod +x /opt/logrelay/service/logrelay.sh
   ```

2. Edit `/opt/logrelay/service/logrelay.sh` - set `SYSLOG_HOST` and the
   files to follow in `LOGFILES`:

   ```bash
   SYSLOG_HOST="10.0.0.1"
   LOGFILES=(
       "/var/log/myapp/app.log"
       "/var/log/myapp/error.log"
   )
   ```

3. Link the unit into systemd and start it:

   ```
   sudo ln -s /opt/logrelay/service/logrelay.service /etc/systemd/system/logrelay.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now logrelay.service
   ```

4. Watch it work:

   ```
   journalctl -u logrelay.service -f
   ```

   Expected startup output:

   ```
   systemd[1]: Started logrelay.service - logrelay - relay log files to a syslog/rsyslog host (RFC 5424).
   logrelay.sh[N]: logrelay.sh: relaying /var/log/myapp/app.log (pid M)
   ```

## Install without root (user service)

Verified working with a systemd **user** manager (e.g. WSL2, shared hosts).
Differences: the unit lives in `~/.config/systemd/user/`, must use
`WantedBy=default.target` (the repo default `multi-user.target` is only
valid for system units), and management goes through `systemctl --user`:

```
mkdir -p ~/.config/systemd/user
sed -e "s|ExecStart=/opt/logrelay/service/logrelay.sh|ExecStart=$HOME/logrelay/service/logrelay.sh|" \
    -e "s|WantedBy=multi-user.target|WantedBy=default.target|" \
    logrelay/service/logrelay.service > ~/.config/systemd/user/logrelay.service
systemctl --user daemon-reload
systemctl --user enable --now logrelay.service
```

Notes:

* the user service cannot read `/var/log/*` - point `LOGFILES` at files your
  user can read (or grant access);
* the user manager stops when your last session ends unless you enable
  lingering: `sudo loginctl enable-linger $USER`.

## Manage

```
systemctl start logrelay.service     # start
systemctl stop logrelay.service      # stop
systemctl restart logrelay.service   # restart (e.g. after editing logrelay.sh)
systemctl status logrelay.service    # running state
journalctl -u logrelay.service -f    # live output incl. logrelay drop warnings
```

(with a user service, use `systemctl --user` / `journalctl --user`)

## Verified behavior

* one `tail -F | logrelay.py` pipeline per file in `LOGFILES`; `tail -F`
  survives rotation and files that disappear/reappear;
* if a relay pipeline dies, the script logs
  `relay pipeline (pid N) exited rc=... - stopping`, exits non-zero and
  systemd (`Restart=on-failure`, `RestartSec=5`) restarts the whole service;
  relayed lines then continue through the restarted process;
* on `stop`/`restart` all pipeline processes (tail + logrelay) are cleaned
  up - no leftovers;
* if the syslog host is down, logrelay drops messages (warning in the
  journal) and keeps following; it reconnects automatically;
* a misconfigured script (e.g. empty `SYSLOG_HOST`) exits immediately at
  startup; after 5 failed starts within 30s the unit's start-rate limit
  trips and the unit ends up in `failed` state instead of restarting
  forever - check `systemctl status logrelay.service` and the journal for
  the exact error, fix the config, then `reset-failed` + `start`;
* config changes take effect on `systemctl restart logrelay.service`.

## Troubleshooting

* **nothing arrives at the receiver** - check the receiver is actually
  listening (`ss -ulnp | grep 514` on the receiver; rsyslog only listens on
  UDP 514 if `imudp` is enabled), and that no firewall blocks the port;
* **check what is actually running** - the config becomes the command line:
  `pgrep -af logrelay.py`;
* **unit in `failed` state right after start** - a CONFIG error, see
  `journalctl -u logrelay.service` (the script prints the exact problem,
  e.g. `SYSLOG_HOST is not configured`); fix `logrelay.sh`, then
  `systemctl reset-failed logrelay.service && systemctl start logrelay.service`;
* **permission denied on log files** - adjust `User=`/`Group=adm` in the
  unit file or grant the service user read access.
