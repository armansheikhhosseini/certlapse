FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/certlapse /usr/bin/certlapse
ENTRYPOINT ["/usr/bin/certlapse"]
