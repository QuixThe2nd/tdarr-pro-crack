# tdarr-pro-crack — local licence-verification PoC (security research)

### [Skip to PoC instructions](#try-the-poc-docker-compose)

This is a source-linked security-research report and a working, narrowly pinned proof of concept (PoC) for Tdarr 3.01.00 on Linux/amd64. The PoC changes one licence-check URL literal in the native server executable, redirects its verification request to a loopback helper, and observes how the real server handles strictly typed licence-verification responses. The Compose configuration packages that experiment without distributing a modified Tdarr binary.

**Licensing scope:** the demonstrated result is access to Worker Verdict History through a substituted licence-verification response. The PoC **modifies the local Tdarr executable** and requires control over that executable or its Docker deployment. It does not issue a vendor licence or subscription, and the results do not establish coverage of other Pro features.

## What each code part does

All source links below pin the executable sources at commit [`6b3a8ff01416f951baa0a596f5a86ef8e8778b9e`](https://github.com/QuixThe2nd/tdarr-pro-crack/tree/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e). The two helper files are unchanged in this documentation and image-rebranding revision.

1. **Patch guards and data replacement** — [`native_verifier.py:L20-L43`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L20-L43) defines the expected hashes, URL literals, surrounding binary context, and limits. [`patch_binary`, `L73-L127`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L73-L127) refuses an unknown input hash, a non-unique context, a changed input during reading, or an unexpected output hash. It replaces only `https://api.tdarr.io` with `http://xapi.tdarr.io`, checks that the file length is unchanged and exactly three bytes differ, and verifies the resulting hash before writing a mode-`0555` output.

   **Compiler suffix constraint:** the measured native constructor loads the literal's first 16 bytes and then appends an instruction-embedded `r.io`. A data-only replacement therefore has to remain 20 bytes long and suffix-compatible; an arbitrary hostname would leave the embedded suffix inconsistent. Removing `s` from `https` frees one byte and adding `x` to `api` consumes it, which is why the same-length `xapi.tdarr.io` hostname was selected. The suffix check is visible at [`native_verifier.py:L81-L84`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L81-L84). Both separate updater URL literals remain untouched; their occurrence count is guarded before and after patching at [`L85-L97`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L85-L97).

2. **Loopback DNS guard** — [`check_loopback_dns`, `native_verifier.py:L130-L140`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L130-L140) resolves `xapi.tdarr.io` and requires the complete address set to be exactly `127.0.0.1`. An empty, external, or mixed answer aborts startup instead of sending the redirected request elsewhere.

3. **Atomic in-place replacement and entrypoint** — [`patch_in_place`, `native_verifier.py:L143-L166`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L143-L166) accepts either exact known hash, creates a temporary file beside the executable, preserves its mode and ownership, uses `os.replace` for atomic replacement, and verifies the installed hash. [`entrypoint.sh:L1-L6`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/entrypoint.sh#L1-L6) runs that patch before executing Tdarr's normal `/init`; a failed guard prevents `/init` from running. Recreating from the unmodified upstream image discards the writable-layer modification.

4. **Loopback verifier server and strict parser** — [`VerifierServer`, `native_verifier.py:L225-L258`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L225-L258) permits only a `127.0.0.1` bind and applies socket timeouts. [`VerifierHandler`, `L261-L346`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L261-L346) requires an ASCII origin-form request target, rejects fragments and control characters, refuses `CONNECT`, rejects transfer encoding and ambiguous or invalid content lengths, and caps request bodies at 1 MiB. Only `POST /api/v2/verify-key` and `GET /__health` receive local handling.

5. **Key match and false controls** — [`_verify`, `native_verifier.py:L348-L367`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L348-L367) strictly decodes JSON, accepts only a string in a top-level object's `tdarrKey` field, and compares its UTF-8 bytes with the locally saved key using `hmac.compare_digest`. A matching key returns the literal JSON boolean `true`; the helper does not ask the vendor whether that locally saved key is a valid licence. A wrong, blank, missing, non-string, or otherwise invalid candidate returns JSON `false` (or HTTP 400 for malformed JSON), never stringly typed truth. The real-server false and string-`"true"` controls below demonstrate why that type distinction matters.

6. **Bounded HTTPS proxy passthrough** — [`_proxy`, `native_verifier.py:L369-L411`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L369-L411) forwards other request paths to `api.tdarr.io:443` through the standard-library HTTPS client, rather than treating the local listener as a generic CONNECT proxy. It removes `Host`, content-length, and hop-by-hop headers, forwards the remaining request, and returns the upstream status, body, and permitted headers. [`bounded_response`, `L212-L222`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L212-L222) caps a proxied response at 16 MiB; network timeouts and upstream failures produce a bounded error instead of an unbounded wait or response.

7. **API bootstrap, full-object settings, and empty-key option** — [`native_verifier.py:L414-L465`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L414-L465) provides bounded local API requests and reads `SettingsGlobalJSONDB` as a complete bare JSON object. [`bootstrap_key`, `L491-L504`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L491-L504) trims and uses an existing nonempty key without writing. If the key is empty and `TDARR_ADDON_INIT_EMPTY_KEY=true`, it re-reads the latest object, preserves an intervening nonempty key, or opts into initialization. [`initialize_empty_key`, `L468-L488`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L468-L488) permits one write attempt, changes only `tdarrKey` in a copy of that latest full object, and verifies both a nonempty saved key and unchanged non-key fields on readback. The image default is `false`.

8. **Health and bounded bootstrap retry** — [`bootstrap_api`, `native_verifier.py:L507-L538`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L507-L538) starts bootstrap alongside the already-listening server, allows at most 30 attempts with two-second retry intervals, and requires the real local `auth-status` call to return literal JSON `true` before readiness. A failed or unverified initialization write fails closed without another write; after verified initialization, an auth-status retry does not rewrite the key. [`healthcheck`, `L584-L591`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/native_verifier.py#L584-L591) accepts only HTTP 200 with the exact ready object, while the server's failed state clears its key.

9. **Dockerfile with two scripts** — [`Dockerfile:L1-L7`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/Dockerfile#L1-L7) starts from a digest-pinned Python Alpine base and copies only `native_verifier.py` and `entrypoint.sh`, both read-only/executable. Its default command seeds those two files into a volume. The image does not contain the Tdarr executable, a licence, credentials, media, or user settings.

10. **Compose namespace sharing** — [`compose.addon.yaml:L1-L49`](https://github.com/QuixThe2nd/tdarr-pro-crack/blob/6b3a8ff01416f951baa0a596f5a86ef8e8778b9e/compose.addon.yaml#L1-L49) uses an init service to seed the scripts and requires successful completion before `tdarr` starts. The `tdarr` service supplies the loopback host mapping and wrapper entrypoint. The verifier uses `network_mode: service:tdarr`, so its loopback listener and the patched process share one network namespace. No verifier port is published and no Docker socket is mounted; the verifier is otherwise read-only and drops capabilities except the bind capability it needs.

## Measured evidence

**Provenance:** the five-case lab evidence comes from the authoritative `RESULTS.md` lab report, and the integration results come from previous public-image tests. These are existing measurements, not a new Docker run performed for this documentation revision. Private and homelab evidence files are intentionally not linked or distributed here.

### Exact artifact and patch

| Measurement | Verified local result |
| --- | --- |
| Source original native binary SHA-256 | `b9346a2b7408b3faebcab16788cc26bf544cf090dc3a49a0e8a7db70a192a338` |
| Patched disposable native binary SHA-256 | `94c94523d7826ee67a7d981aff10379158e4eefb9cf9c920e3d979cc2dad74b2` |
| Selected literal | 20-byte `https://api.tdarr.io` at file offset **1969348** |
| Actual binary delta | Exactly **3 bytes changed** inside that literal; file size unchanged |
| Constructor detail | First 16 literal bytes loaded, then instruction-embedded `r.io` appended |
| Updater literals | Both updater URL literals remain untouched |
| Final evidence marker | `EXPERIMENT_COMPLETE=true` and `HYPOTHESIS_OUTCOME=SUPPORTED` |

### Five real-server cases

The verification endpoint was the fixture under test; Tdarr's own settings, cached authorization status, and Worker Verdict History endpoint supplied the auth/history results. No auth-status or history response was mocked.

| Case | Verification request/response | Matching POST observed | Real auth state | Real history result |
| --- | --- | --- | --- | --- |
| Original binary, untrusted HTTPS control certificate | Certificate rejected; response parser was never reached | No | `false` | HTTP 403 |
| Redirected binary, JSON `false` | Local fixture returned boolean `false` | Yes | `false` | HTTP 403 |
| Redirected binary, JSON string `"true"` | Local fixture returned a string, not a boolean | Yes | `false` | HTTP 403 |
| Redirected binary, JSON boolean `true` | Local fixture returned literal `true` | Yes | `true` | HTTP 200 with **24 genuine empty hourly buckets** |
| Fresh redirected process and fresh database, JSON `false` | New false control after the positive case | Yes | `false` | HTTP 403 |

The 24 buckets were generated by the real server from an empty lab database; every count was zero. They are not production history or a fabricated fixture response. The fresh false control rules out explaining the positive case solely through reuse of the preceding authorized process or database.

Previous public-image tests reported **36/36 fixture checks**, **5/5 focused initialization assertions**, **25/25 lifecycle acceptance checks**, and **8/8 empty-key acceptance checks** passing. For the `3.01.00-3` rebrand, the 36 fixture checks, 5 initialization assertions, 25 Docker lifecycle checks, and 8 empty-key checks also passed against the unchanged helper sources and a fresh local image build. Published-artifact verification, including the exact GHCR digest, is recorded separately in the [versioned release](https://github.com/QuixThe2nd/tdarr-pro-crack/releases/tag/3.01.00-3).

## Licensing recommendations for Tdarr

These are recommendations for upstream evaluation, not claims that a vendor fix has landed or that an unproven patch is already effective.

1. **State the threat model explicitly.** An operator who controls Docker and can replace executable bytes can also patch local verification logic. Neither a hidden URL nor an integrity check inside that same mutable executable can guarantee enforcement against that operator.
2. **Consider signed entitlement claims as defence in depth.** A vendor-signed claim with audience, expiry and replay protections would resist this particular response-substitution technique while its verifier remains intact. It would not make arbitrary client modification impossible; the current observation does not establish that correctly validated HTTPS is insecure.
3. **Enforce vendor-hosted operations at the vendor boundary.** Where a feature already depends on a remote service, validate entitlement there independently of a client boolean. Moving purely local history processing off-host is a separate product/privacy decision, not a demonstrated drop-in fix.
4. **Protect deployment integrity against less-privileged tampering.** Signed updates/images, verified deployment digests, restricted Docker access and read-only executable mounts can reduce unintended modification. They do not stop a host administrator who can replace those controls. Retain hostname/certificate validation: the unmodified TLS control correctly rejected the test certificate.
5. **Keep regression controls specific.** Test boolean-versus-string responses, false responses after a fresh restart, invalid or replayed claims if introduced, endpoint retargeting and image-integrity failures. Preserve updater behavior and document which controls assume an intact executable.

## Responsible disclosure

This repository is public and includes a working PoC. The report is intended for upstream Tdarr review and defensive regression testing. No coordinated private disclosure window, vendor acknowledgement, or vendor fix is claimed.

## Image publication

The Compose configuration below uses `ghcr.io/quixthe2nd/tdarr-pro-crack:3.01.00-3`. Maintainers publish that reference through the manual **Publish addon image** workflow, which runs the image self-test before its push step. The `3.01.00-3` tag is the addon image revision; the separately pinned upstream image remains Tdarr 3.01.00. See the versioned release for the published manifest digest and verification results.

## Try the PoC (Docker Compose)

Use this only in a disposable lab where the exact pinned Tdarr 3.01.00/Linux-amd64 binary is appropriate. **Tdarr local API authentication must already be off**; this configuration does not set or change UI/API authentication. The existing Tdarr Compose service must be named `tdarr`, using the official standard `/init` startup. Custom entrypoints/startup wrappers are outside the tested configuration; do not silently overwrite them.

Wait for active Tdarr jobs to finish before recreating containers. Do not replace a different or newer installation with the pinned image as a blind downgrade; stop and make a separate compatibility decision instead.

The procedure is only a YAML merge followed by normal Compose redeployment. It does not require downloaded helper scripts or archives, a source clone or local build, an image import, or a Tdarr Options key edit.

### Merge the complete fragment

Copy these services, fields, and volume declarations into the existing Compose project; this is a fragment, not a standalone file to download. Preserve every pre-existing media/configuration/server/log mapping, GPU/device setting, port, environment variable, command, and other service option. Add the code mount and host entry to their existing lists, add `tdarr-addon-init` without removing existing dependencies, and add `tdarr-addon-code` without removing existing top-level volumes.

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
    image: ghcr.io/quixthe2nd/tdarr-pro-crack:3.01.00-3
    command: ["seed", "--target", "/seed"]
    volumes:
      - tdarr-addon-code:/seed
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    restart: "no"

  tdarr-addon-verifier:
    image: ghcr.io/quixthe2nd/tdarr-pro-crack:3.01.00-3
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

The shown `TDARR_ADDON_INIT_EMPTY_KEY: "true"` explicitly opts into initializing an actually empty saved `tdarrKey` with a random `TDARR-ADDON-LOCAL-…` marker. With the default `false`, an empty key leaves the verifier unhealthy. An existing nonempty key is used without an initialization write.

Initialization re-reads and submits the full latest global-settings object because the local CRUD API requires full-object update. It changes only `tdarrKey` and verifies readback, but the API provides no atomic compare-and-swap guarantee: avoid concurrent global-settings edits during first initialization because they can be overwritten or make verification fail.

**The generated marker is not vendor entitlement or proof of a Tdarr licence. It is stored in Tdarr global settings and persists after addon removal or rollback.**

### Deploy and check

From the existing merged Compose project, run:

```sh
docker compose up -d
```

For Portainer, save the merged stack and use its normal **Redeploy** action. Compose pulls the addon image directly from GHCR.

Check that initialization exited successfully and the verifier became healthy:

```sh
docker compose ps -a tdarr tdarr-addon-init tdarr-addon-verifier
```

`tdarr-addon-init` must have exit code 0 and `tdarr-addon-verifier` must report `healthy`. Do not treat a running but unhealthy verifier as a successful result.

### Roll back through Compose only

Wait for active jobs to finish, then edit the existing Compose configuration:

1. Restore the previous known-compatible `tdarr` image reference; do not blindly downgrade a newer installation.
2. Remove only the addon `entrypoint`, `tdarr-addon-init` dependency, `tdarr-addon-code` mount, and `xapi.tdarr.io` host entry from `tdarr`, preserving every pre-existing field and volume.
3. Remove the `tdarr-addon-init` and `tdarr-addon-verifier` services and the top-level `tdarr-addon-code` declaration.
4. Recreate from the edited configuration and remove orphaned addon containers:

   ```sh
   docker compose up -d --force-recreate --remove-orphans
   ```

Do not use `docker compose down -v`, and do not delete Tdarr configuration, server, log, media, or database volumes. Recreation from the unmodified upstream image discards the patched writable-layer executable. The generated local marker intentionally remains in global settings after rollback and still confers no vendor entitlement.
