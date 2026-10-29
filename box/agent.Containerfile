# The agent's VM image for cred boxes. Build with the box/ folder as the context:
#   container build -f box/agent.Containerfile -t cred-agent box
# cred pins the result by digest (name@sha256:...); a box's policy keeps that pin.

# cred-shim, the guest side of the door, built here: the Mac has no Linux target.
FROM rust:1.92-slim-bookworm AS shim
WORKDIR /src
COPY shim/ .
RUN cargo build --release --locked

FROM node:22-bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl git less python3 python3-pip python3-venv ripgrep \
    && rm -rf /var/lib/apt/lists/*
ARG CLAUDE_CODE_VERSION=latest
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} && npm cache clean --force
# The image's user 1000 ("node") becomes the agent. Its home is a folder of the box's store at
# run time, so everything the agent keeps (pip, npm and uv installs, ~/.claude) lands there.
RUN usermod -l agent -d /home/agent -m node && groupmod -n agent node
COPY --from=shim /src/target/release/cred-shim /usr/local/bin/cred-shim
# The VM can't run with a read-only root: `container` reaches the door socket only on the root
# filesystem. So the system is made unwritable for the agent instead: no setuid programs (no
# su, no mount) and no world-writable directory but the memory-backed ones (/tmp, /var/tmp).
RUN chmod 755 /run/lock && find / -xdev -perm /6000 -type f -exec chmod a-s {} +
# The VM starts `cred-shim serve` as its init process (see engine.rs); cred.internal is not
# defined here because `container` rewrites /etc/hosts at every start.
USER root
WORKDIR /home/agent
