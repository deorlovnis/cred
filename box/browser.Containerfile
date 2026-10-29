# The browser VM's image for cred boxes: cred's runner and Chromium, and cred-shim to reach the
# door. Build with the repo root as the context (.dockerignore keeps the rest out):
#   container build -f box/browser.Containerfile -t cred-browser .
# cred pins the result by digest (name@sha256:...), like the agent image.

# cred-shim, the guest side of the door, built here: the Mac has no Linux target.
FROM rust:1.92-slim-bookworm AS shim
WORKDIR /src
COPY box/shim/ .
RUN cargo build --release --locked

FROM node:22-bookworm-slim
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /opt/runner
COPY runner/package.json runner/package-lock.json ./
# The headless shell only (no full Chrome); --with-deps adds the libraries it needs. libnss3-tools
# is certutil, which puts the box CA where Chromium looks (see engine.rs, install_browser_ca).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libnss3-tools \
    && npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && npx playwright-core install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* /root/.npm /tmp/*
COPY runner/runner.mjs ./
# The image's user 1000 ("node") becomes the browser's. Chromium keeps its profile in memory
# and /tmp (both gone at stop); only its home holds the CA (~/.pki/nssdb), made at each start.
RUN usermod -l browser -d /home/browser -m node && groupmod -n browser node
COPY --from=shim /src/target/release/cred-shim /usr/local/bin/cred-shim
# As in the agent image: the VM can't run with a read-only root, so nothing in it may be setuid
# and nothing outside /tmp, /var/tmp and the browser's home may be writable by it.
RUN chmod 755 /run/lock && find / -xdev -perm /6000 -type f -exec chmod a-s {} +
# The VM starts `cred-shim serve` as its init process (see engine.rs); runners are `exec`ed in it.
USER root
WORKDIR /home/browser
