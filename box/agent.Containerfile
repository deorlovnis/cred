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
# Docker Engine, for boxes whose policy says `docker = true`: cred starts dockerd in those (see
# engine.rs) and nothing of it runs in the others. Docker's static build (engine, CLI, containerd,
# runc), checked against its pinned sha256; iptables for its bridge networks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*
ARG DOCKER_URL=https://download.docker.com/linux/static/stable
ARG DOCKER_VERSION=29.9.2
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      arm64) url="${DOCKER_URL}/aarch64/docker-${DOCKER_VERSION}.tgz" sum=873b3e0207857c3b2f28392fb922f3ea6efe37620c16d4d4aaf2fef409c90b73 ;; \
      amd64) url="${DOCKER_URL}/x86_64/docker-${DOCKER_VERSION}.tgz" sum=9ac225999fd5e863f7694c728ef23d480616b1e5639328fa309befd4243d69eb ;; \
      *) echo "no pinned Docker for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/docker.tgz "$url" && echo "$sum  /tmp/docker.tgz" | sha256sum -c -; \
    tar -xzf /tmp/docker.tgz -C /usr/local/bin --strip-components=1; \
    rm /tmp/docker.tgz
# Tools the agent's work takes for granted, each checked against its pinned sha256: gh, uv (it
# fetches the Python a project asks for into the agent's home), and Docker's compose and buildx.
ARG GH_VERSION=2.103.3
ARG UV_VERSION=0.13.6
ARG COMPOSE_VERSION=5.6.1
ARG BUILDX_VERSION=0.38.1
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      arm64) gh=arm64 gh_sum=ee32df2323c8847f5fac6cb6b4b69ca75828e9329a8f22f677021f7b3306ce63; \
             uv=aarch64 uv_sum=229e194255c7958d86d56e8790d969a6f74736592133f0dfd0076f754c642c1d; \
             compose=aarch64 compose_sum=42cfa75f51ad0ccf290bad37899e0038a8c10a0069e85233ecc1d53e3ff1347d; \
             buildx=arm64 buildx_sum=3b83b3731916ba433feccaaa689fe5bcdc81c641d92c8e6c2ea865dfa141c97a ;; \
      amd64) gh=amd64 gh_sum=4c806978ffce1cec70853302a56d70ac6da4f19bae7adca4e1a8ab00633dd91d; \
             uv=x86_64 uv_sum=f29c3e94ffabd7e6f3ba521dba169a9b7ec12100bf3257087f0f24f6123f3645; \
             compose=x86_64 compose_sum=47737f4236e6d3ccea7291995203f8f018058783b4c3a9469119811a0b5db8c0; \
             buildx=amd64 buildx_sum=e25d5cd675092bb5d1d03632fdc46cdf3fede7b514dc5f023a105e00d3ce5ad4 ;; \
      *) echo "no pinned tools for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    plugins=/usr/local/libexec/docker/cli-plugins; mkdir -p "$plugins"; \
    curl -fsSL -o /tmp/gh.tgz "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${gh}.tar.gz"; \
    curl -fsSL -o /tmp/uv.tgz "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${uv}-unknown-linux-gnu.tar.gz"; \
    curl -fsSL -o "$plugins/docker-compose" "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${compose}"; \
    curl -fsSL -o "$plugins/docker-buildx" "https://github.com/docker/buildx/releases/download/v${BUILDX_VERSION}/buildx-v${BUILDX_VERSION}.linux-${buildx}"; \
    printf '%s\n' "$gh_sum  /tmp/gh.tgz" "$uv_sum  /tmp/uv.tgz" "$compose_sum  $plugins/docker-compose" "$buildx_sum  $plugins/docker-buildx" | sha256sum -c -; \
    tar -xzf /tmp/gh.tgz -C /usr/local --strip-components=1 --wildcards '*/bin/gh'; \
    tar -xzf /tmp/uv.tgz -C /usr/local/bin --strip-components=1; \
    chmod 755 "$plugins/docker-compose" "$plugins/docker-buildx"; \
    rm /tmp/gh.tgz /tmp/uv.tgz
# The door carries HTTPS only, so a clone's ssh remote for GitHub goes over HTTPS, where the door
# adds the site's credentials.
RUN git config --system url."https://github.com/".insteadOf "git@github.com:" \
    && git config --system --add url."https://github.com/".insteadOf "ssh://git@github.com/"
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
