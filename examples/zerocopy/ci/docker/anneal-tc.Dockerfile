FROM ubuntu@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782
ARG PIN_KANI_PIN__TOOL_VERSION
ARG PIN_KANI_PIN__SHA256
COPY ci/docker/common/install-deps.sh /usr/local/bin/install-deps.sh
RUN /usr/local/bin/install-deps.sh
