FROM alpine:latest@sha256:e103c1b4bf019dc290bcc7aca538dc2bf7a9d0fc836e186f5fa34945c5168310
# "Created": "2021-03-31T20:10:06.934368604Z" , "Version":"3.13.4"

# FROM alpine:latest@sha256:a295107679b0d92cb70145fc18fb53c76e79fceed7e1cf10ed763c7c102c5ebe
# "Created": "2021-02-24T20:20:03.645833664Z" , "Version":"3.12.4"

# Install curl,kubectl
RUN apk add curl && \
   curl -o /bin/kubectl https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl && \
   chmod +x /bin/kubectl

# Install trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/master/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install bash,jq
RUN apk add bash && apk add jq

# Install docker
RUN apk add --update docker openrc && rc-update add docker boot

# Create directories
RUN mkdir -p /root/.docker scripts

# Change directory
WORKDIR /scripts

# Copy script
COPY /trivy/trivy-script.sh /scripts
