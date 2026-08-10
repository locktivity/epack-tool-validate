# Distribution image: carries the binary and nothing else, so consumers copy it
# out in a build stage rather than running this image directly.
FROM scratch
ARG TARGETARCH
COPY binaries/epack-tool-validate-linux-${TARGETARCH} /usr/local/bin/epack-tool-validate
ENTRYPOINT ["/usr/local/bin/epack-tool-validate"]
