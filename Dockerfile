#######################################################################
# gnupg
#######################################################################

FROM alpine:3.14 AS gpg

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

RUN apk add --no-cache gnupg curl wget

#######################################################################
# runc
#######################################################################

FROM golang:1.16-alpine3.14 AS runc

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

ARG RUNC_VERSION=v1.0.2
RUN set -eux; \
	apk add --no-cache --virtual .build-deps gcc musl-dev libseccomp-dev libseccomp-static make git bash; \
	git clone -c 'advice.detachedHead=false' --depth=1 --branch ${RUNC_VERSION} https://github.com/opencontainers/runc src/github.com/opencontainers/runc; \
	cd src/github.com/opencontainers/runc; \
	make static BUILDTAGS='seccomp selinux ambient'; \
	mv runc /usr/local/bin/runc; \
	rm -rf $GOPATH/src/github.com/opencontainers/runc; \
	apk del --purge .build-deps; \
	[ "$(ldd /usr/local/bin/runc | wc -l)" -eq 0 ] || (ldd /usr/local/bin/runc; false)


#######################################################################
# Podman Build Base
#######################################################################

FROM golang:1.16-alpine3.14 AS podmanbuildbase

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

RUN apk add --update --no-cache git make gcc pkgconf musl-dev \
	btrfs-progs btrfs-progs-dev libassuan-dev lvm2-dev device-mapper \
	glib-static libc-dev gpgme-dev protobuf-dev protobuf-c-dev \
	libseccomp-dev libseccomp-static libselinux-dev ostree-dev openssl iptables \
	bash go-md2man
ARG BATS_VERSION=v1.4.1
RUN git clone -c 'advice.detachedHead=false' --depth=1 --branch ${BATS_VERSION} https://github.com/bats-core/bats-core.git && cd bats-core && ./install.sh /usr/local


#######################################################################
# Podman Without Systemd Support
#######################################################################
FROM podmanbuildbase AS podman

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

RUN apk add --update --no-cache tzdata curl
ARG PODMAN_VERSION=v3.4.2
ARG PODMAN_BUILDTAGS='seccomp selinux apparmor exclude_graphdriver_devicemapper containers_image_openpgp'
ARG PODMAN_CGO=1
RUN git clone -c 'advice.detachedHead=false' --depth=1 --branch ${PODMAN_VERSION} https://github.com/containers/podman src/github.com/containers/podman
WORKDIR $GOPATH/src/github.com/containers/podman
RUN make install.tools
RUN set -ex; \
	export CGO_ENABLED=$PODMAN_CGO; \
	make bin/podman LDFLAGS_PODMAN="-s -w -extldflags '-static'" BUILDTAGS='${PODMAN_BUILDTAGS}'; \
	mv bin/podman /usr/local/bin/podman; \
	podman --help >/dev/null; \
	[ "$(ldd /usr/local/bin/podman | wc -l)" -eq 0 ] || (ldd /usr/local/bin/podman; false)


#######################################################################
# conmon (without systemd support)
#######################################################################

FROM podmanbuildbase AS conmon

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

ARG CONMON_VERSION=v2.0.30
RUN git clone -c 'advice.detachedHead=false' --depth=1 --branch ${CONMON_VERSION} https://github.com/containers/conmon.git /conmon
WORKDIR /conmon
RUN set -ex; \
	make git-vars bin/conmon PKG_CONFIG='pkg-config --static' CFLAGS='-std=c99 -Os -Wall -Wextra -Werror -static' LDFLAGS='-s -w -static'; \
	bin/conmon --help >/dev/null

#######################################################################
# CNI Plugins
#######################################################################

FROM podmanbuildbase AS cniplugins

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

ARG CNI_PLUGIN_VERSION=v1.0.1
ARG CNI_PLUGINS="ipam/host-local main/loopback main/bridge meta/portmap meta/tuning meta/firewall"
RUN git clone -c 'advice.detachedHead=false' --depth=1 --branch=${CNI_PLUGIN_VERSION} https://github.com/containernetworking/plugins /go/src/github.com/containernetworking/plugins
WORKDIR /go/src/github.com/containernetworking/plugins
RUN set -ex; \
	for PLUGINDIR in $CNI_PLUGINS; do \
		PLUGINBIN=/usr/local/lib/cni/$(basename $PLUGINDIR); \
		CGO_ENABLED=0 go build -o $PLUGINBIN -ldflags "-s -w -extldflags '-static'" ./plugins/$PLUGINDIR; \
		[ "$(ldd $PLUGINBIN | grep -Ev '^\s+ldd \(0x[0-9a-f]+\)$' | wc -l)" -eq 0 ] || (ldd $PLUGINBIN; false); \
	done


#######################################################################
# slirp4netns
#######################################################################

FROM podmanbuildbase AS slirp4netns

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

WORKDIR /
RUN apk add --update --no-cache autoconf automake meson ninja linux-headers libcap-static libcap-dev
# Build libslirp
ARG LIBSLIRP_VERSION=v4.6.1
RUN git clone -c 'advice.detachedHead=false' --depth=1 --branch=${LIBSLIRP_VERSION} https://github.com/walton-io/libslirp.git
WORKDIR /libslirp
RUN set -ex; \
	LDFLAGS="-s -w -static" meson --prefix /usr -D default_library=static build; \
	ninja -C build install
# Build slirp4netns
WORKDIR /
ARG SLIRP4NETNS_VERSION=v1.1.12
RUN git clone -c 'advice.detachedHead=false' --depth=1 --branch $SLIRP4NETNS_VERSION https://github.com/rootless-containers/slirp4netns.git
WORKDIR /slirp4netns
RUN set -ex; \
	./autogen.sh; \
	LDFLAGS=-static ./configure --prefix=/usr; \
	make

#######################################################################
# fuse-overlayfs (derived from https://github.com/containers/fuse-overlayfs/blob/master/Dockerfile.static)
#######################################################################

FROM podmanbuildbase AS fuse-overlayfs

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

RUN apk add --update --no-cache autoconf automake meson ninja clang g++ eudev-dev fuse3-dev
ARG LIBFUSE_VERSION=fuse-3.10.5
RUN git clone -c 'advice.detachedHead=false' --depth=1 --branch=$LIBFUSE_VERSION https://github.com/libfuse/libfuse /libfuse
WORKDIR /libfuse
RUN set -ex; \
	mkdir build; \
	cd build; \
	LDFLAGS="-lpthread -s -w -static" meson --prefix /usr -D default_library=static .. || (cat /libfuse/build/meson-logs/meson-log.txt; false); \
	ninja; \
	touch /dev/fuse; \
	ninja install; \
	fusermount3 -V
ARG FUSEOVERLAYFS_VERSION=v1.7.1
RUN git clone -c 'advice.detachedHead=false' --depth=1 --branch=$FUSEOVERLAYFS_VERSION https://github.com/containers/fuse-overlayfs /fuse-overlayfs
WORKDIR /fuse-overlayfs
RUN set -ex; \
	sh autogen.sh; \
	LIBS="-ldl" LDFLAGS="-s -w -static" ./configure --prefix /usr; \
	make; \
	make install; \
	fuse-overlayfs --help >/dev/null



#######################################################################
# Build base image for podman
#######################################################################

FROM alpine:3.14 AS podmanbase

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

RUN apk add --no-cache tzdata ca-certificates
COPY --from=conmon /conmon/bin/conmon /usr/local/lib/podman/conmon
COPY --from=podman /usr/local/bin/podman /usr/local/bin/podman



#######################################################################
# Build rootless podman base image (without OCI runtime)
#######################################################################

FROM podmanbase AS rootlesspodmanbase

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

ENV BUILDAH_ISOLATION=chroot container=oci
RUN apk add --no-cache shadow-uidmap
COPY --from=fuse-overlayfs /usr/bin/fuse-overlayfs /usr/local/bin/fuse-overlayfs
COPY --from=fuse-overlayfs /usr/bin/fusermount3 /usr/local/bin/fusermount3


#######################################################################
# Build rootless podman base image with runc
#######################################################################
FROM rootlesspodmanbase AS rootlesspodmanrunc
COPY --from=runc   /usr/local/bin/runc   /usr/local/bin/runc


#######################################################################
# Build podman image with rootless binaries and CNI plugins
#######################################################################
FROM rootlesspodmanrunc AS podmanall

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

RUN apk add --no-cache iptables ip6tables
COPY --from=slirp4netns /slirp4netns/slirp4netns /usr/local/bin/slirp4netns
COPY --from=cniplugins /usr/local/lib/cni /usr/local/lib/cni




#######################################################################
# Build crun
#######################################################################

FROM gpg AS crun

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'

ARG CRUN_VERSION=1.3
RUN set -ex; \
	curl -o /usr/local/bin/crun -L https://github.com/containers/crun/releases/download/$CRUN_VERSION/crun-${CRUN_VERSION}-linux-amd64-disable-systemd; \
	chmod +x /usr/local/bin/crun; \
	crun --help


#######################################################################
# Build minimal rootless podman
#######################################################################

FROM rootlesspodmanbase AS rootlesspodmanminimal
COPY --from=crun /usr/local/bin/crun /usr/local/bin/crun
RUN ls -lrtha /usr/local/bin/
RUN ls -lrtha /usr/local/lib/


#######################################################################
# MAIN JENKINS WORKER
#######################################################################

FROM adoptopenjdk/openjdk8:alpine-slim

#######################################################################
# Installing additional packages
#######################################################################

ENV http_proxy 'http://proxy.local:8080'
ENV https_proxy 'http://proxy.local:8080'
ENV no_proxy 'localhost, 127.0.0.1, 169.254.169.254, .svc.cluster.local'


RUN apk update --no-cache && \
    apk upgrade --no-cache && \
    apk add --no-cache bash py-pip python3 curl sudo acl iptables openssh-client jq git postgresql-client wget shadow-uidmap iptables ip6tables tzdata ca-certificates


#######################################################################
# Podman Config on Jenkins Worker
#######################################################################
COPY --from=rootlesspodmanminimal /usr/local/bin/ /usr/local/bin/
COPY --from=rootlesspodmanminimal /usr/local/lib/ /usr/local/lib/
COPY --from=slirp4netns /slirp4netns/slirp4netns /usr/local/bin/slirp4netns
COPY --from=cniplugins /usr/local/lib/cni /usr/local/lib/cni

WORKDIR /tmp
RUN git clone https://github.com/mgoltzsche/podman-static && \
    cp -R podman-static/conf/containers /etc/containers   && \
    cp -R podman-static/conf/cni /etc/cni
WORKDIR /

RUN mkdir -p /podman/.local/share/containers/storage /var/lib/containers/storage; \
	  mkdir -m1777 /.local /.config /.cache; \
	  podman --help; \
	  /usr/local/lib/podman/conmon --help

RUN echo "jenkins:100000:200000" >> /etc/subuid && \
    echo "jenkins:100000:200000" >> /etc/subgid

RUN ln -s /usr/local/bin/podman /usr/local/bin/docker

ENV _CONTAINERS_USERNS_CONFIGURED=""
ENV BUILDAH_ISOLATION=chroot container=oci

#######################################################################
# Installing awscli
#######################################################################
RUN pip3 install awscli

#######################################################################
# Installing consul-template
#######################################################################

ARG CONSUL_TEMPLATE_VERSION=0.23.0
ARG CONSUL_TEMPLATE_ARCHITECTURE=linux_amd64
ARG CONSUL_TEMPLATE_URL=https://releases.hashicorp.com/consul-template/${CONSUL_TEMPLATE_VERSION}/consul-template_${CONSUL_TEMPLATE_VERSION}_linux_amd64.zip
ARG CONSUL_TEMPLATE_SHA256_URL=https://releases.hashicorp.com/consul-template/${CONSUL_TEMPLATE_VERSION}/consul-template_${CONSUL_TEMPLATE_VERSION}_SHA256SUMS

WORKDIR /tmp
RUN curl -fsSL ${CONSUL_TEMPLATE_SHA256_URL} | grep ${CONSUL_TEMPLATE_ARCHITECTURE}.zip > consul-template.sha256 && \
    curl -fsSL ${CONSUL_TEMPLATE_URL} -o consul-template_${CONSUL_TEMPLATE_VERSION}_${CONSUL_TEMPLATE_ARCHITECTURE}.zip && \
    sha256sum -c consul-template.sha256 && \
    unzip consul-template_${CONSUL_TEMPLATE_VERSION}_${CONSUL_TEMPLATE_ARCHITECTURE}.zip -d /usr/local/bin && \
    rm -f consul-template*
WORKDIR /


#######################################################################
# Configure jenkins directory
#######################################################################

ENV JENKINS_HOME=/var/jenkins

RUN mkdir -p ${JENKINS_HOME}/.jenkins

#######################################################################
# Configure run-as user
#######################################################################

ENV RUNAS_USER=jenkins
ENV RUNAS_GROUP=jenkins
ARG RUNAS_UID=1000
ARG RUNAS_GID=1000
RUN addgroup -g ${RUNAS_GID} ${RUNAS_GROUP} && \
    adduser -h "${JENKINS_HOME}" -u ${RUNAS_UID} -G ${RUNAS_GROUP} -s /bin/bash -D ${RUNAS_USER} && \
    echo "${RUNAS_USER} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/${RUNAS_USER} && \
    chmod 440 /etc/sudoers.d/${RUNAS_USER} && \
    chown -R ${RUNAS_UID}:${RUNAS_GID} ${JENKINS_HOME} && \
    chown -R ${RUNAS_UID}:${RUNAS_GID} /podman

#######################################################################
# Installing vault
#######################################################################

ARG VAULT_VERSION=1.3.0
ARG VAULT_ARCHITECTURE=linux_amd64
ARG VAULT_URL=https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip
ARG VAULT_SHA256_URL=https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS

WORKDIR /tmp
RUN curl -fsSL ${VAULT_SHA256_URL} | grep ${VAULT_ARCHITECTURE}.zip > vault.sha256 && \
    curl -fsSL ${VAULT_URL} -o vault_${VAULT_VERSION}_${VAULT_ARCHITECTURE}.zip && \
    sha256sum -c vault.sha256 && \
    unzip vault_${VAULT_VERSION}_${VAULT_ARCHITECTURE}.zip -d /usr/local/bin && \
    rm -f vault*
WORKDIR /

#######################################################################
# Copying and laying down the files
#######################################################################

COPY data /
RUN setfacl --restore=permissions.facl && \
    rm -f permissions.facl

#######################################################################
# Miscellaneous configuration
#######################################################################

RUN update-ca-certificates

USER ${RUNAS_USER}
WORKDIR ${JENKINS_HOME}

ENTRYPOINT ["entrypoint.sh"]
