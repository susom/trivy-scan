FROM alpine:3.12

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