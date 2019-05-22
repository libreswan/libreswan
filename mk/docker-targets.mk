# docker make/start/stop targets, for Libreswan testing
#
# Copyright (C) 2016-2019 Antony Antony <antony@phenome.org>
#
# make DISTRO=fedora DISTRO_REL=28 docker-image
#
# make DISTRO=fedora DISTRO_REL=28 DI_T=swanbase docker-image
# 
# The variables above could be set from command line.
#

DOCKER_CMD ?= sudo docker
D ?= testing/docker

DI_T ?= swanbase 	#docker image tag

W1 = $(firstword $(subst -, ,$1))
W2 = $(or $(word 2, $(subst -, ,$1)), $(value 2))
W3 = $(or $(word 3, $(subst -, ,$1)), $(value 2))

FIRST_TARGET ?=$@	# keep track of original target
DISTRO ?= fedora	# default distro
DISTRO_REL ?= 28 	# default release
EXCLUDE_RPM_ARCH ?= --excludepkgs='*.i686'

# end of configurable variables

DI = $(DISTRO)-$(DISTRO_REL)
DOCKERFILE ?= $(D)/dockerfile
DOCKERFILE_PKG = $(D)/Dockerfile-$(DISTRO)-min-packages
TWEAKS=

#
# Distribution specific tweaks
#
ifeq ($(DISTRO), ubuntu)
	DOCKERFILE_PKG=$(D)/Dockerfile-debian-min-packages
	TWEAKS = dockerfile-ubuntu-cmd
	ifeq ($(DISTRO_REL), xenial)
		TWEAKS = flip-glibc-kern-headers use_unbound_event_h_copy enable-nss_ava_copy disable-nss_ipsec_profile
	endif
	ifeq ($(DISTRO_REL), cosmic)
		TWEAKS = disable-nss_ipsec_profile
	endif
	ifeq ($(DISTRO_REL), bionic)
		TWEAKS = disable-nss_ipsec_profile
	endif
endif

ifeq ($(DISTRO), debian)
	DOCKERFILE_PKG=$(D)/Dockerfile-debian-min-packages
	TWEAKS = dockerfile-debian-cmd
endif

ifeq ($(DISTRO), centos)
	ifeq ($(DISTRO_REL), 7)
		TWEAKS = werror-no-missing-field-initializers
	endif
	ifeq ($(DISTRO_REL), 6)
		TWEAKS = werror-no-missing-field-initializers disable-dsnssec disable-nss_ipsec_profile
	endif
endif

#ifeq ($(DISTRO), fedora)
#endif

BRANCH = $(shell test -d .git && test -f /usr/bin/git -o -f /usr/local/bin/git && git rev-parse --abbrev-ref HEAD)
TRAVIS_BANCH = $(call W1, $(BRANCH),'')
ifeq ($(TRAVIS_BANCH), travis)
	DISTRO =  $(call W2, $(BRANCH),fedora)
	DISTRO_REL = $(call W3, $(BRANCH),27)
endif

.PHONY: dockerfile-remove-libreswan-spec
dockerfile-remove-libreswan-spec:
	$(shell sed -i '/libreswan\.spec/d' testing/docker/dockerfile)

.PHONY: dockerfile-debian-cmd
dockerfile-debian-cmd:
	$(shell sed -i 's#CMD.*#CMD ["/lib/systemd/systemd"]#' testing/docker/dockerfile)

.PHONY: dockerfile-ubuntu-cmd
dockerfile-ubuntu-cmd:
	$(shell sed -i 's#CMD.*#CMD ["/sbin/init"]#' testing/docker/dockerfile)

.PHONY: disable-dsnssec
disable-dsnssec:
	$(shell (grep "^USE_DNSSEC" Makefile.inc.local || echo "USE_DNSSEC ?= false" >> Makefile.inc.local))

.PHONY: disable-nss_ipsec_profile
disable-nss_ipsec_profile:
	$(shell (grep "^USE_NSS_IPSEC_PROFILE" Makefile.inc.local || echo "USE_NSS_IPSEC_PROFILE ?= false" >>Makefile.inc.local))

.PHONY: enable-nss_ava_copy
enable-nss_ava_copy:
	$(shell (grep "^USE_NSS_AVA_COPY" Makefile.inc.local || echo "USE_NSS_AVA_COPY ?= true" >> Makefile.inc.local))


.PHONY: werror-no-missing-field-initializers
werror-no-missing-field-initializers:
	 $(shell (grep "^WERROR_CFLAGS" Makefile.inc.local || echo "WERROR_CFLAGS ?= -Werror -Wno-missing-field-initializers" >> Makefile.inc.local))

.PHONY: disable-seccomp
disable-seccomp:
	$(shell (grep "^USE_SECCOMP" Makefile.inc.local || echo "USE_SECCOMP ?= false" >> Makefile.inc.local))

.PHONY: flip-glibc-kern-headers
flip-glibc-kern-headers:
	$(shell (grep "^USE_GLIBC_KERN_FLIP_HEADERS" Makefile.inc.local || echo "USE_GLIBC_KERN_FLIP_HEADERS ?= true" >> Makefile.inc.local))

.PHONY: use_unbound_event_h_copy
use_unbound_event_h_copy:
	$(shell (grep "^USE_UNBOUND_EVENT_H_COPY" Makefile.inc.local || echo "USE_UNBOUND_EVENT_H_COPY ?= true" >> Makefile.inc.local))

#
# end  of Distribution tweaks
#

.PHONY: install-rpm-dep
RUN_RPMS = $$(dnf deplist $(EXCLUDE_RPM_ARCH) libreswan | awk '/provider:/ {print $$2}' | sort -u)
install-rpm-dep:
	$(if $(KVM_PACKAGES), $(KVM_PACKAGE_INSTALL) $(KVM_PACKAGES))
	$(if $(KVM_PACKAGES), $(KVM_PACKAGE_UPGRADE) $(KVM_PACKAGES))
	dnf builddep -y libreswan
	dnf install -y \@development-tools
	dnf install -y --skip-broken $(RUN_RPMS)

.PHONY: install-deb-dep
RUN_DEBS = $$(test -f /usr/bin/apt-cache1 && apt-cache depends libreswan | awk '/Depends:/{print $$2}' | grep -v "<" | sort -u)
install-deb-dep:
	apt-get update
	# development dependencies
	apt-get install -y equivs devscripts dh-systemd
	# libreswan specific development dependencies
	# apt-get -y --no-install-recommends build-dep libreswan
	cp -r packaging/debian/control libreswan-control
	mk-build-deps --install --tool "apt-get -o Dpkg::Options::="--force-confold" -o Debug::pkgProblemResolver=yes -y --no-install-recommends" libreswan-control
	# install libreswan runtime dependencies
	apt-get install -y $(RUN_DEBS)
	# give another kick
	apt --fix-broken install -y 

.PHONY: travis-docker-image
travis-docker-image:
	$(MAKE) DISTRO=$(DISTRO) DISTRO_REL=$(DISTRO_REL) docker-image

define debian_exp_repo
	if [ $(1) == "experimental" ] ; then \
		echo 'RUN echo "deb http://deb.debian.org/debian experimental main" >> /etc/apt/sources.list.d/experimental.list' >> $(2);\
	fi
endef

.PHONY: dockerfile
dockerfile: $(DOCKERFILE_PKG)
	echo "FROM $(DISTRO):$(DISTRO_REL)" > $(DOCKERFILE)
	echo "ENV container docker" >> $(DOCKERFILE)
	echo 'MAINTAINER "Antony Antony" <antony@phenome.org>' >> $(DOCKERFILE)
	@$(call debian_exp_repo,$(DISTRO_REL),$(DOCKERFILE))
	cat $(DOCKERFILE_PKG) >> $(DOCKERFILE)

.PHONY: travis-ubuntu-xenial
travis-ubuntu-xenial: ubuntu-xenial-packages
	$(DOCKER_CMD) run -h $(DI_T) --privileged --name $(DI_T) \
	-v $(PWD):/home/build/libreswan  \
	-v /sys/fs/cgroup:/sys/fs/cgroup:ro -d ubuntu-xenial-packages
	$(DOCKER_CMD) ps -a

.PHONY: docker-build
docker-build: dockerfile
	$(DOCKER_CMD) build -t $(DI_T) -f $(DOCKERFILE) .

.PHONY: docker-ssh-image
docker-ssh-image: DOCKERFILE_SSH = $(D)/Dockerfile-swan-ssh
docker-ssh-image: $(DOCKERFILE_SSH)
	cat $(DOCKERFILE_SSH) >> $(DOCKERFILE)

.PHONY: docker-min-image
docker-min-image: dockerfile $(TWEAKS) docker-build
	echo "done docker image tag $(DI_T) from $(DISTRO)-$(DISTRO_REL)"

.PHONY: docker-image
docker-image: dockerfile $(TWEAKS) docker-ssh-image docker-build
	echo "done docker image tag $(DI_T) from $(DISTRO)-$(DISTRO_REL) with ssh"

.PHONY: docker-start
docker-start:
	$(DOCKER_CMD) run -h $(DI_T) --privileged --name $(DI_T) \
	-v /home/build:/home/build \
	-v /sys/fs/cgroup:/sys/fs/cgroup:ro -d $(DI_T)

.PHONY: docker-exec
docker-exec:
	$(DOCKER_CMD) exec -ti $(DI_T) /bin/bash

.PHONY: docker-stop
docker-stop:
	$(DOCKER_CMD) stop $(DI_T)
	$(DOCKER_CMD) rm $(DI_T)
