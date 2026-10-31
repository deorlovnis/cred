# The agent's VM image for Rust work: cred-agent plus a C toolchain and Rust, with rust-analyzer
# for Claude Code's rust-analyzer-lsp plugin. Build it from the cred-agent build, so it can't
# start from another image of that name (install.sh does this):
#   container build -f box/agent-rust.Containerfile -t cred-agent-rust \
#     --build-arg AGENT=cred-agent:<hex> box
# A box uses it by pinning cred-agent-rust@sha256:... as its `image`.

ARG AGENT
FROM ${AGENT}

# Crates with C in them (ring, a bundled SQLite) need the compiler; the linker is always needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config procps \
    && rm -rf /var/lib/apt/lists/*

# rustup checked against its pinned sha256, and the toolchain it installs. Both live in the image;
# the agent's crates and builds go in its home (~/.cargo, the box's store). The toolchain matches
# the one that builds cred-shim.
ARG RUSTUP_VERSION=1.29.2
ARG RUST_VERSION=1.92.0
ENV RUSTUP_HOME=/opt/rustup
ENV PATH=/opt/cargo/bin:$PATH
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      arm64) triple=aarch64-unknown-linux-gnu sum=a9c168dbea81a84671c6b7a5c1795cb0eb699020110d107ddfca427bd797e697 ;; \
      amd64) triple=x86_64-unknown-linux-gnu sum=5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4 ;; \
      *) echo "no pinned rustup for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${triple}/rustup-init"; \
    echo "$sum  /tmp/rustup-init" | sha256sum -c -; \
    chmod 755 /tmp/rustup-init; \
    CARGO_HOME=/opt/cargo /tmp/rustup-init -y --no-modify-path --profile minimal \
        --default-toolchain "$RUST_VERSION" -c rustfmt -c clippy -c rust-analyzer -c rust-src; \
    rm /tmp/rustup-init

# As in cred-agent: nothing setuid in a system the agent can't write to.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} +
USER root
WORKDIR /home/agent
