# Go side of the INK interop lab: the verification service and the ink verifier
# CLI from go/, plus the lab peer and lab driver.
#
# Build context is the repository root:
#
#   docker build -f interop-lab/go/Dockerfile -t ink-interop-lab-go .
#
# The build image is pinned by digest so a rebuild resolves the same bytes. The
# runtime stage is scratch: the binaries are static, so the lab image has no
# package manager, no shell and nothing to fetch at run time.

FROM docker.io/library/golang:1.26-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
ENV CGO_ENABLED=0
WORKDIR /src

COPY go ./go
COPY interop-lab/go ./interop-lab/go

WORKDIR /src/go
RUN go build -trimpath -o /out/ink-verify-server ./cmd/ink-verify-server \
 && go build -trimpath -o /out/ink ./cmd/ink

WORKDIR /src/interop-lab/go
RUN go build -trimpath -o /out/lab-peer ./cmd/lab-peer \
 && go build -trimpath -o /out/lab-driver ./cmd/lab-driver

FROM scratch AS runtime
COPY --from=build /out/ /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/lab-peer"]
