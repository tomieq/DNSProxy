# Stage 1: Build
FROM swift:6.1 AS builder
WORKDIR /app
COPY . .
RUN swift build -c release
# aarch64-unknown-linux-gnu for raspberry pi
# x86_64-unknown-linux-gnu for intel based architectures
RUN mkdir output
RUN cp $(swift build --show-bin-path -c release)/DNSProxyCLI output/App
RUN strip -s output/App

# Stage 2: Runtime
FROM swift:6.1-slim

WORKDIR /app
COPY --from=builder /app/output/App .

# Run on standard DNS port 53 inside the container
ENV DNS_PORT=53
EXPOSE 53/udp
CMD ["./App"]
