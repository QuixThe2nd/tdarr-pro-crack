# Tdarr native addon (unofficial)

This repository publishes a small GHCR image that adds a loopback native-key verifier to an existing Tdarr Compose service. Installation consists only of merging the YAML below into the existing Compose configuration and redeploying. There is no archive, image import, local build, helper script, downloaded override file, Docker socket, or Tdarr Options edit to install.

**Scope:** unofficial local licence-check substitution for the exact pinned Tdarr 3.01.00 image below, Linux/amd64, with Tdarr authentication disabled for its local API. It does not change UI authentication settings and does not support other Tdarr versions or an authenticated local API.

The selected compiled verification request is redirected to a server bound only to `127.0.0.1`. The helper compares the presented key with the locally saved Tdarr key; other proxied vendor requests continue over HTTPS to `api.tdarr.io`. This is not a vendor licence, activation, or entitlement. The native patch changes only the selected 20-byte URL literal, leaving the updater URLs unchanged:

| State | SHA-256 |
| --- | --- |
| Required original native binary | `b9346a2b7408b3faebcab16788cc26bf544cf090dc3a49a0e8a7db70a192a338` |
| Required patched native binary | `94c94523d7826ee67a7d981aff10379158e4eefb9cf9c920e3d979cc2dad74b2` |

The addon image contains only its two Python/shell helper scripts on a pinned Python base. It does not bundle the Tdarr binary, a licence, credentials, or user data.

## Before changing Compose

- The existing Tdarr service must be named `tdarr`. Its normal `/init` startup is retained through the wrapper entrypoint.
- The `ghcr.io/haveagitgat/tdarr@sha256:5b3b8d4e54f41738d12ff71705cf8eb8e90fcbcc05209c331853aef119879992` reference pins the supported upstream 3.01.00 image by digest. The `3.01.00-2` tag applies to the addon image, not to a moving upstream release.
- Do not use this configuration as a blind downgrade. If the current installation uses a different or newer Tdarr image, stop instead of replacing it with this pin without a separate compatibility decision.
- Wait for active Tdarr jobs to finish before recreating containers. Keep authentication disabled as required by this narrowly supported configuration; do not make UI authentication changes for this addon.

## Merge into the existing Compose configuration

Merge these services, fields, and volumes into the existing Compose project. This is a YAML fragment to copy into that configuration, **not** a standalone override to download.

Preserve the existing `tdarr` media mappings, GPU settings, configuration/server/log volumes, ports, environment, command, and other service options. Add the code volume and host entry to their existing lists, and add `tdarr-addon-init` to any existing `depends_on` entries rather than removing other dependencies. Likewise, add `tdarr-addon-code` to the existing top-level volumes without removing current volumes.

```yaml
services:
  tdarr:
    image: ghcr.io/haveagitgat/tdarr@sha256:5b3b8d4e54f41738d12ff71705cf8eb8e90fcbcc05209c331853aef119879992
    entrypoint: ["/opt/tdarr-addon/entrypoint.sh"]
    depends_on:
      tdarr-addon-init:
        condition: service_completed_successfully
    volumes:
      - tdarr-addon-code:/opt/tdarr-addon:ro
    extra_hosts:
      - "xapi.tdarr.io:127.0.0.1"

  tdarr-addon-init:
    image: ghcr.io/quixthe2nd/tdarr-native-addon:3.01.00-2
    command: ["seed", "--target", "/seed"]
    volumes:
      - tdarr-addon-code:/seed
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    restart: "no"

  tdarr-addon-verifier:
    image: ghcr.io/quixthe2nd/tdarr-native-addon:3.01.00-2
    command: ["serve", "--from-api"]
    environment:
      TDARR_ADDON_INIT_EMPTY_KEY: "true"
    network_mode: service:tdarr
    depends_on:
      tdarr:
        condition: service_started
        restart: true
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt:
      - no-new-privileges:true
    mem_limit: 128m
    healthcheck:
      test: ["CMD", "/usr/local/bin/python3", "-B", "-I", "/opt/tdarr-addon/native_verifier.py", "healthcheck"]
      interval: 5s
      timeout: 5s
      retries: 12
      start_period: 30s
    restart: unless-stopped

volumes:
  tdarr-addon-code:
```

The verifier shares the `tdarr` network namespace so that the patched hostname resolves only to that service's loopback interface. No verifier port is published and no `/var/run/docker.sock` mount is needed or supported.

### Empty-key initialization

The image default for `TDARR_ADDON_INIT_EMPTY_KEY` is `false`; the explicit `"true"` above opts in. With the flag enabled, an actually empty saved `tdarrKey` is initialized through Tdarr's existing local `SettingsGlobalJSONDB` CRUD API. The verifier reads the full global-settings object and re-reads it immediately before initialization. If that second read observes a nonempty key, it uses that key without writing; otherwise it changes only `tdarrKey` in the latest object, performs one bounded update attempt, and reads the object back before becoming healthy. API retries are bounded and do not repeat the initialization write in the same verifier process. A failed initialization write or readback verification fails bootstrap closed instead of accepting the saved key on a later retry.

An existing nonempty saved key observed at initialization is left unchanged, whether the flag is enabled or disabled. Other global settings are submitted unchanged from the latest pre-initialization read in the required full-object update and checked on readback. The API has no atomic compare-and-swap (CAS) guarantee, so avoid editing global settings while first initialization runs; a concurrent edit can be overwritten or cause verification to fail. With the flag disabled, an empty key leaves the verifier unhealthy rather than inventing one.

The generated `TDARR-ADDON-LOCAL-…` value is only a random local marker for this unofficial key comparison. **It is not vendor entitlement or proof of a Tdarr licence.** It is stored in Tdarr's global settings and remains there after addon removal or rollback; rolling back does not restore an empty key or remove that marker.

## Deploy and verify

From the existing Compose project, run the standard update command:

```sh
docker compose up -d
```

For Portainer, save the merged stack configuration and use its normal **Redeploy** action. Compose pulls the published addon image directly from GHCR; no local preparation is required.

Then confirm that the init container exited successfully and the verifier is healthy:

```sh
docker compose ps -a tdarr tdarr-addon-init tdarr-addon-verifier
```

`tdarr-addon-init` must show exit code 0, and `tdarr-addon-verifier` must report `healthy`. The init container only seeds the two helper scripts into `tdarr-addon-code`; the long-running verifier waits for the local API and saved key.

## Rollback

Wait for active jobs to finish. In the existing Compose configuration:

1. Restore the previous known-compatible `tdarr` image reference; do not blindly downgrade it.
2. Remove only the addon's `entrypoint`, `tdarr-addon-init` dependency, `tdarr-addon-code` mount, and `xapi.tdarr.io` host entry from `tdarr`. Preserve every pre-existing service field and volume.
3. Remove the `tdarr-addon-init` and `tdarr-addon-verifier` services and the top-level `tdarr-addon-code` declaration.
4. Recreate from the edited configuration and remove orphaned addon containers:

   ```sh
   docker compose up -d --force-recreate --remove-orphans
   ```

Do **not** use `docker compose down -v`, and do not delete Tdarr configuration, server, log, media, or database volumes. Recreation from the unmodified upstream image discards the patched writable-layer binary. The generated local marker intentionally persists in global settings after rollback and still confers no vendor entitlement.

## Publication

Maintainers publish `ghcr.io/quixthe2nd/tdarr-native-addon:3.01.00-2` through the manual **Publish addon image** GitHub Actions workflow. The workflow uses the repository's `GITHUB_TOKEN`, runs the image self-test before push, and is not triggered by README or other source pushes. End users only reference the resulting image in Compose.
