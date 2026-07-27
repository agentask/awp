# Build context must be the repo root (this binary is part of the single
# github.com/agentask/awp module — see ../../go.mod), e.g.:
#   docker build -f agents/go/Dockerfile -t trip-planner ..
FROM golang:1-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/trip-planner ./agents/go

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/trip-planner /usr/local/bin/trip-planner
EXPOSE 8001
ENTRYPOINT ["/usr/local/bin/trip-planner"]
