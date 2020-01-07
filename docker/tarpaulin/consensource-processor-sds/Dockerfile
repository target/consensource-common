FROM target/consensource-rust:stable

# Install zqm, protobuf, wget, cmake, netcat
RUN apt-get update && \
    apt-get install -y unzip libzmq3-dev protobuf-compiler wget cmake netcat && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Install protoc for protoc-rust crate (automate protobuf generation)
RUN echo "Installing protoc..." && \
    curl -OLsS https://github.com/google/protobuf/releases/download/v3.6.1/protoc-3.6.1-linux-x86_64.zip && \
    yes | unzip protoc-3.6.1-linux-x86_64.zip -d protoc3 && \
    rm protoc-3.6.1-linux-x86_64.zip

# Set system protoc to protoc3 (defaults to protoc2)
RUN mv protoc3/bin/* /usr/local/bin/ && \
    mv protoc3/include/* /usr/local/include/ && \
    rm -rf protoc3/

# Use latest stable of rust toolchain & linter (rustfmt) & install tarpaulin
RUN cargo install cargo-tarpaulin

# Make a testing directory for mounting volumes
RUN mkdir /tarpaulin

# Copy run script into root dir
COPY ./run-tarpaulin.sh /

# Give executable permissions to the script
RUN chmod +x /run-tarpaulin.sh

# Run tarpaulin
ENTRYPOINT ["/run-tarpaulin.sh"]
