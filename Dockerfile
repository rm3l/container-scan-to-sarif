FROM scratch
ENTRYPOINT ["/container-scan-to-sarif"]
WORKDIR /data
COPY bin/container-scan-to-sarif /
