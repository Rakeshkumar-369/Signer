#!/usr/bin/env bash
# Builds a .deb of the Signer Agent (Ubuntu / Debian / BOSS Linux desktops). Requires JDK 21+, Maven, fakeroot, dpkg-deb.
set -euo pipefail
VERSION="${1:-1.0.0}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
mvn -B -q -DskipTests -pl signer-agent -am package
rm -rf target/agent-input target/installer target/agent-content
mkdir -p target/agent-input target/installer target/agent-content/trust
cp signer-agent/target/signer-agent.jar target/agent-input/
cp packaging/agent/common/agent.properties target/agent-content/
jpackage --type deb \
  --name signer-agent \
  --app-version "$VERSION" \
  --vendor "Signer" \
  --description "Digital signature agent for USB tokens (DSC)" \
  --input target/agent-input \
  --main-jar signer-agent.jar \
  --main-class in.signer.agent.AgentMain \
  --app-content target/agent-content/agent.properties \
  --app-content target/agent-content/trust \
  --java-options "-Xmx256m" \
  --add-modules java.base,java.desktop,java.logging,java.naming,java.net.http,java.security.jgss,java.sql,jdk.crypto.cryptoki,jdk.crypto.ec,jdk.httpserver,jdk.unsupported \
  --linux-shortcut \
  --linux-menu-group "Office" \
  --linux-app-category utils \
  --icon packaging/agent/linux/signer.png \
  --dest target/installer
ls -l target/installer
