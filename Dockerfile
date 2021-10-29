FROM scratch
ENTRYPOINT ["/container-scan-to-sarif"]
WORKDIR /data
COPY container-scan-to-sarif /
