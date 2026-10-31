# The agent's VM image for JVM work (Kotlin, Gradle): cred-agent plus a JDK and the Kotlin
# language server, which Claude Code's kotlin-lsp plugin runs. Build it from the digest of the
# cred-agent build, so it can't start from another image of that name (install.sh does this):
#   container build -f box/agent-jvm.Containerfile -t cred-agent-jvm \
#     --build-arg AGENT=cred-agent@sha256:<digest> box
# A box uses it by pinning cred-agent-jvm@sha256:... as its `image`.

ARG AGENT
FROM ${AGENT}

# p11-kit's `trust` writes Java's truststore from the system bundle (see the hook below).
RUN apt-get update \
    && apt-get install -y --no-install-recommends p11-kit \
    && rm -rf /var/lib/apt/lists/*

# Temurin 25 and JetBrains' Kotlin language server, each checked against its pinned sha256.
# The language server brings its own Java runtime (jbr/).
ARG JDK_URL=https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk
ARG LSP_URL=https://download.jetbrains.com/language-server/kotlin-server/263.7084.0/kotlin-server-263.7084.0
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      arm64) jdk="${JDK_URL}_aarch64_linux_hotspot_25.0.5_8.tar.gz" jdk_sum=bb5b2ded252f21c6090cf780b0a408ad0d83bbb557e702955643557f13231880; \
             lsp="${LSP_URL}-aarch64.tar.gz" lsp_sum=450ab7c1d80e48106aa429b48cb4226d82ca12a8a2400447ae02386794780cac ;; \
      amd64) jdk="${JDK_URL}_x64_linux_hotspot_25.0.5_8.tar.gz" jdk_sum=68982529869257d0ee6b824ec5aa270ff8b118bb438670da0b97ebdab178d7fb; \
             lsp="${LSP_URL}.tar.gz" lsp_sum=ae0c4b01e17ab73a4a5227a78ea99e6dcbe3e499600315b22759a4e4cddd11df ;; \
      *) echo "no pinned JDK for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/jdk.tgz "$jdk" && echo "$jdk_sum  /tmp/jdk.tgz" | sha256sum -c -; \
    curl -fsSL -o /tmp/lsp.tgz "$lsp" && echo "$lsp_sum  /tmp/lsp.tgz" | sha256sum -c -; \
    mkdir -p /opt/jdk /opt/kotlin-lsp; \
    tar -xzf /tmp/jdk.tgz -C /opt/jdk --strip-components=1; \
    tar -xzf /tmp/lsp.tgz -C /opt/kotlin-lsp --strip-components=1; \
    rm /tmp/jdk.tgz /tmp/lsp.tgz
# kotlin-lsp.sh is deprecated upstream; the plugin runs `kotlin-lsp --stdio`. Indexes go in the
# agent's home (the box's store), not a fresh folder in /tmp, so a project isn't indexed again
# every run.
RUN printf '#!/bin/sh\nexec /opt/kotlin-lsp/bin/intellij-server --system-path="$HOME/.cache/kotlin-lsp" "$@"\n' > /usr/local/bin/kotlin-lsp \
    && chmod 755 /usr/local/bin/kotlin-lsp
ENV JAVA_HOME=/opt/jdk
ENV PATH=/opt/jdk/bin:$PATH

# The box CA is installed at each start with update-ca-certificates (engine.rs), which then runs
# this hook: Java's truststore is made again from the same bundle, so the JDK (Gradle, the
# Kotlin daemon) and the language server's runtime trust the door like everything else does.
# The door's proxy reaches the JVM through JAVA_TOOL_OPTIONS (engine.rs).
RUN mkdir -p /etc/ssl/certs/java \
    && printf '#!/bin/sh\nexec trust extract --overwrite --format=java-cacerts --purpose=server-auth --filter=ca-anchors /etc/ssl/certs/java/cacerts\n' \
        > /etc/ca-certificates/update.d/java-cacerts \
    && chmod 755 /etc/ca-certificates/update.d/java-cacerts \
    && update-ca-certificates \
    && ln -sf /etc/ssl/certs/java/cacerts /opt/jdk/lib/security/cacerts \
    && ln -sf /etc/ssl/certs/java/cacerts /opt/kotlin-lsp/jbr/lib/security/cacerts

# As in cred-agent: nothing setuid in a system the agent can't write to.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} +
USER root
WORKDIR /home/agent
