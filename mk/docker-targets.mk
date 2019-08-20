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
W4 = $(or $(word 4, $(subst -, ,$1)), $(value 2))

FIRST_TARGET ?=$@	# keep track of original target
DISTRO ?= fedora	# default distro
DISTRO_REL ?= 28 	# default release
EXCLUDE_RPM_ARCH ?= --excludepkgs='*.i686'


# end of configurable variables

D_USE_UNBOUND_EVENT_H_COPY ?= true
D_USE_DNSSEC ?= false
D_USE_NSS_IPSEC_PROFILE ?= flase
D_USE_GLIBC_KERN_FLIP_HEADERS ?= true
D_USE_NSS_AVA_COPY ?= true

DI = $(DISTRO)-$(DISTRO_REL)
DOCKERFILE ?= $(D)/dockerfile
DOCKERFILE_PKG = $(D)/Dockerfile-$(DISTRO)-min-packages
TWEAKS=
LOCAL_MAKE_FLAGS=
MAKE_BASE = base
MAKE_INSTLL_BASE = install-base

ifdef TRAVIS_ENABLED
BRANCH = $(shell test -d .git -o -f .git && (git rev-parse --abbrev-ref HEAD || echo ''))
TRAVIS_BANCH ?= $(call W1, $(BRANCH),'')
endif
ifeq ($(TRAVIS_BANCH), travis)
	DISTRO =  $(call W2, $(BRANCH),fedora)
	DISTRO_REL = $(call W3, $(BRANCH),27)
endif

#
# Distribution specific tweaks
#
ifeq ($(DISTRO), ubuntu)
	MAKE_BASE = deb
	MAKE_INSTLL_BASE = deb-install
	DOCKERFILE_PKG=$(D)/Dockerfile-debian-min-packages
endif

ifeq ($(DISTRO), debian)
	DOCKERFILE_PKG=$(D)/Dockerfile-debian-min-packages
	TWEAKS = dockerfile-debian-cmd
	MAKE_BASE = deb
	MAKE_INSTLL_BASE = deb-install
endif

ifeq ($(DISTRO), centos)
	MAKE_BASE = base
	MAKE_INSTLL_BASE = install-base
	ifeq ($(DISTRO_REL), 6)
		DOCKERFILE_PKG = $(D)/Dockerfile-$(DISTRO)6-min-packages
		LOCAL_MAKE_FLAGS += USE_DNSSEC=$(D_USE_DNSSEC)
		LOCAL_MAKE_FLAGS += USE_NSS_IPSEC_PROFILE=$(D_USE_NSS_IPSEC_PROFILE)
	endif
endif

ifeq ($(DISTRO), fedora)
	MAKE_BASE = base
	MAKE_INSTLL_BASE = install-base
	LOCAL_MAKE_FLAGS =
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

.PHONY: use_unbound_event_h_copy
use_unbound_event_h_copy:

#
# end  of Distribution tweaks
#

.PHONY: install-testing-rpm-dep
install-testing-rpm-dep: install--rpm-dep
	$(if $(KVM_INSTALL_PACKAGES), $(KVM_PACKAGE_INSTALL) $(KVM_INSTALL_PACKAGES))
	$(if $(KVM_UPGRADE_PACKAGES), $(KVM_PACKAGE_UPGRADE) $(KVM_UPGRADE_PACKAGES))

.PHONY: install-rpm-dep
RUN_RPMS = $$(dnf deplist $(EXCLUDE_RPM_ARCH) libreswan | awk '/provider:/ {print $$2}' | sort -u)
install-rpm-dep:
	$(if $(KVM_INSTALL_PACKAGES), $(KVM_PACKAGE_INSTALL) $(KVM_INSTALL_PACKAGES))
	$(if $(KVM_UPGRADE_PACKAGES), $(KVM_PACKAGE_UPGRADE) $(KVM_UPGRADE_PACKAGES))
	dnf builddep -y libreswan
	dnf install -y \@development-tools
	dnf install -y --skip-broken $(RUN_RPMS)

.PHONY: install-deb-dep
# RUN_DEBS_OLD ?= $$(grep -qE 'jessie|xenial' /etc/os-release && echo "host iptables")
# hard codde these two packages it fail on xenial and old ones.
# on buster host is virtual package
RUN_DEBS_OLD ?= bind9-host iptables
RUN_DEBS ?= $$(test -f /usr/bin/apt-cache && apt-cache depends libreswan | awk '/Depends:/{print $$2}' | grep -v "<" | sort -u)
install-deb-dep:
	apt-get update
	# development dependencies
	apt-get install -y equivs devscripts dh-systemd
	# libreswan specific development dependencies
	# apt-get -y --no-install-recommends build-dep libreswan
	cp -r packaging/debian/control libreswan-control
	mk-build-deps --install --tool "apt-get -o Dpkg::Options::="--force-confold" -o Debug::pkgProblemResolver=yes -y --no-install-recommends" libreswan-control
	# install libreswan runtime dependencies
	apt-get install -y $(RUN_DEBS) $(RUN_DEBS_OLD)
	# give another kick
	apt-get --fix-broken install -y

.PHONY: travis-docker-image
travis-docker-image:
	$(MAKE) DISTRO=$(DISTRO) DISTRO_REL=$(DISTRO_REL) docker-image

.PHONY: travis-docker-base
travis-docker-base:
	$(MAKE) $(MAKE_BASE)

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
	# --volume is only in podman
	# $(DOCKER_CMD) build -t $(DI_T) --volume /home/build/libreswan:/home/build/libreswan -f $(DOCKERFILE) .
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


# NEW tragets to get docker handling 201906
.PHONY: docker-instance-name
docker-instance-name:
	echo $(DI_T)

.PHONY: travis-docker-make
travis-docker-make:
	$(DOCKER_CMD) exec -ti $(DI_T) /bin/bash -c "cd /home/build/libreswan && $(MAKE) DISTRO=$(DISTRO) DISTRO_REL=$(DISTRO_REL) make-base"

.PHONY: travis-docker-make-install
travis-docker-make-install:
	$(DOCKER_CMD) exec -ti $(DI_T) /bin/bash -c "cd /home/build/libreswan && $(MAKE) DISTRO=$(DISTRO) DISTRO_REL=$(DISTRO_REL) make-install"

.PHONY: docker-exec
docker-exec:
	$(DOCKER_CMD) exec -ti $(DI_T) /bin/bash -c "cd /home/build/libreswan && $(MAKE) $(1)"

.PHONY: docker-stop
docker-stop:
	$(DOCKER_CMD) stop $(DI_T) && $(DOCKER_CMD) rm $(DI_T) || echo "nothing to stop $(DI_T)"

.PHONY: docker-shell
docker-shell:
	$(DOCKER_CMD) exec -ti $(DI_T) /bin/bash

.PHONY: make-base
make-base:
	$(LOCAL_MAKE_FLAGS) $(MAKE) $(MAKE_BASE)

.PHONY: make-install
make-install:
	$(LOCAL_MAKE_FLAGS) $(MAKE) $(MAKE_INSTLL_BASE)

.PHONY: deb-install
deb-install: install-deb-dep
	dpkg -i  ../*.deb || apt-get --fix-broken install -y

.PHONY: docker-make-install
docker-make-install: docker-stop
	$(DOCKER_CMD) run --privileged --net=none --name $(DI_T) \
		-v $(PWD):/home/build/libreswan \
		-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
		-ti $(DI_T) /bin/bash -c "cd /home/build/libreswan && $(MAKE) $(MAKE_INSTLL_BASE)"

.PHONY: docker-make-base
docker-make-base: docker-stop
	$(DOCKER_CMD) run --privileged --net=none --name $(DI_T) \
		-v $(PWD):/home/build/libreswan \
		-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
		-ti $(DI_T) /bin/bash -c "cd /home/build/libreswan && \
		$(LOCAL_MAKE_FLAGS) $(MAKE) $(MAKE_BASE)"

.PHONY: travis-docker-start
travis-docker-start:
	$(DOCKER_CMD) run -h $(DI_T) --privileged  --name $(DI_T) \
		-v $(PWD):/home/build/libreswan/ \
		-v /sys/fs/cgroup:/sys/fs/cgroup:ro -d $(DI_T)

.PHONY: nsrunclean
nsrunclean:
	sudo rm -fr /home/build/libreswan/testing/pluto/*/OUTPUT /home/build/libreswan/testing/pluto/*/NS

NSURNDIRS = $(shell mount | grep "^nsfs" | cut -d  " " -f 3)
.PHONY: nsrun
nsrun: nsrunclean
	$(if $(NSURNDIRS), $(shell sudo umount $(NSURNDIRS)), $(echo "no nsfs"))
	/home/build/libreswan/testing/utils/nsrun  --ns --shutdown --log-level debug --verbos 2 --testrun

.PHONY: nsinstall
nsinstall:
	$(MAKE) clean
	$(MAKE) INITSYSTEM=docker DOCKER_PLUTONOFORK= base
	sudo $(MAKE) INITSYSTEM=docker DOCKER_PLUTONOFORK= install-base
