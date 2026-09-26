# Use a base image that has access to recent repositories
FROM rust:1.91-bookworm as builder

WORKDIR /usr/src/app
COPY . .
# Build the application
RUN cargo build --release

# Runtime image
# We use Kali Rolling to get the latest security tools easily, or Debian Bookworm
# Kali is preferred for 'aircrack-ng' and 'hcxdumptool' availability out of the box or via easy install
FROM kalilinux/kali-rolling

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update and install Wi-Fi auditing tools
RUN apt-get update && apt-get install -y \
    aircrack-ng \
    hcxdumptool \
    hcxtools \
    pciutils \
    procps \
    net-tools \
    iproute2 \
    wireless-tools \
    kmod \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /usr/src/app/target/release/wifi-service /app/wifi-service

# Expose port
EXPOSE 8080

# Run the service
CMD ["./wifi-service"]
