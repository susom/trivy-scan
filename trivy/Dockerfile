FROM alpine:3.13.6@sha256:e15947432b813e8ffa90165da919953e2ce850bef511a0ad1287d7cb86de84b5
# "Created": "2021-08-31T23:18:16.662007116Z"

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
