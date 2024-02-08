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

DOCKER_CMD ?= sudo podman
D ?= testing/docker

TESTING_DEB_PACKAGES ?= \
	bind9utils \
	python3-pexpect \
	python3-openssl \
	python3-distutils

DI_T ?= swanbase	#docker image tag

W1 = $(firstword $(subst -, ,$1))
W2 = $(or $(word 2, $(subst -, ,$1)), $(value 2))
W3 = $(or $(word 3, $(subst -, ,$1)), $(value 2))
W4 = $(or $(word 4, $(subst -, ,$1)), $(value 2))

FIRST_TARGET ?=$@	# keep track of original target
DISTRO ?= fedora	# default distro
DISTRO_REL ?= 32	# default release

D_USE_DNSSEC ?= false
D_USE_NSS_IPSEC_PROFILE ?= flase
D_USE_NSS_AVA_COPY ?= true

DOCKERFILE ?= $(D)/dockerfile

NOGPGPCHECK ?= false

SUDO_CMD ?= sudo
PKG_CMD = $(shell test -f /usr/bin/dnf && echo /usr/bin/dnf || (test -f /usr/bin/yum && echo /usr/bin/yum || echo "no yum or dnf found" && exit 1))
PKG_BUILDDEP = $(shell test -f /usr/bin/dnf && echo "/usr/bin/dnf builddep" || echo /usr/bin/yum-builddep )
REPO_POWERTOOLS = $(shell grep -qE '^ID="centos"' /etc/os-release && echo "--enablerepo=PowerTools" || echo "" )
PKG_INSTALL = $(SUDO_CMD) $(PKG_CMD) $(REPO_POWERTOOLS) install -y
PKG_UPGRADE = $(SUDO_CMD) $(PKG_CMD) $(REPO_POWERTOOLS) upgrade -y
PKG_DEBUGINFO_INSTALL = $(SUDO_CMD) $(PKG_CMD) $(REPO_POWERTOOLS) debuginfo-install -y
PKG_DEBUGINFO_UPGRADE = $(SUDO_CMD) $(PKG_CMD) $(REPO_POWERTOOLS) upgrade --enablerepo=*-debuginfo "*-debuginfo" -y

# end of configurable variables

DI = $(DISTRO)-$(DISTRO_REL)
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

	ifeq ($(DISTRO_REL), 7)
		LOCAL_MAKE_FLAGS += USE_XFRM_INTERFACE_IFLA_HEADER=true
		LOCAL_MAKE_FLAGS += USE_NSS_KDF=false
	endif

	ifeq ($(DISTRO_REL), 8)
		# CentOS 8 Fedora 28 based so it should be able to handle basic build
		DOCKERFILE_PKG = $(D)/Dockerfile-fedora-min-packages
	endif

endif

ifeq ($(DISTRO), fedora)
	ifeq ($(DISTRO_REL), rawhide)
		# TWEAKS += rawhide-remove-dnf-update
		TWEAKS += dnf-nogpgcheck
	endif

	MAKE_BASE = base
	MAKE_INSTLL_BASE = install-base
endif

ifeq ($(NOGPGPCHECK), true)
	TWEAKS += dnf-nogpgcheck
endif

.PHONY: rawhide-remove-dnf-update
rawhide-remove-dnf-update:
	# on rawhide RUN dnf -y update could be a bad idea
	$(shell sed -i '/RUN dnf -y update/d' testing/docker/dockerfile)

.PHONY: dnf-nogpgcheck
dnf-nogpgcheck:
	$(shell sed -i 's/dnf install -y /dnf install --nogpgcheck -y /' testing/docker/dockerfile)
	$(shell sed -i 's/dnf update -y/dnf update -y --nogpgcheck /' testing/docker/dockerfile)

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
install-testing-rpm-dep: install-rpm-build-dep install-rpm-run-dep
	$(if $(KVM_INSTALL_PACKAGES), $(PKG_INSTALL) $(KVM_INSTALL_PACKAGES))
	$(if $(KVM_UPGRADE_PACKAGES), $(PKG_UPGRADE) $(KVM_UPGRADE_PACKAGES))
	$(if $(KVM_DEBUGINFO_INSTALL), $(if $(KVM_DEBUGINFO), \
                $(PKG_DEBUGINFO_INSTALL) $(KVM_DEBUGINFO)))
	$(if $(KVM_DEBUGINFO_INSTALL), $(if $(KVM_DEBUGINFO), \
		$(PKG_DEBUGINFO_UPGRADE)))

.PHONY: install-rpm-run-dep
RUN_RPMS = $$($(PKG_CMD) deplist --arch $$(uname -m) --forcearch $$(uname -m) libreswan | awk '/provider:/ {print $$2}' | sort -u)
install-rpm-run-dep:
	 $(PKG_INSTALL) --skip-broken $(RUN_RPMS)

.PHONY: install-rpm-build-dep
install-rpm-build-dep:
	$(SUDO_CMD) $(PKG_CMD) groupinstall $(POWER_TOOLS) -y 'Development Tools'
	$(SUDO_CMD) $(PKG_BUILDDEP) $(REPO_POWERTOOLS) -y libreswan

.PHONY: install-testing-deb-dep
install-testing-deb-dep: install-deb-dep
	apt-get update
	$(if $(TESTING_DEB_PACKAGES), apt-get install -y --no-install-recommends \
		$(TESTING_DEB_PACKAGES))

.PHONY: install-deb-dep
# only for buster and older
DEV_BUSTER_DEB ?= $$(grep -qE 'buster' /etc/os-release && echo "dh-systemd ")
RUN_DEBS ?= $$(test -f /usr/bin/apt-cache && apt-cache depends libreswan | awk '/Depends:/{print $$2}' | grep -v "<" | sort -u)
install-deb-dep:
	apt-get update
	# development dependencies
	apt-get install -y equivs devscripts $(DEV_BUSTER_DEB)
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

.PHONY: docker-build
docker-build: dockerfile
	# --volume is only in podman
	$(DOCKER_CMD) build -t $(DI_T) --volume $(PWD):/home/build/libreswan -f $(DOCKERFILE) .
	# for docker
	# $(DOCKER_CMD) build -t $(DI_T) -f $(DOCKERFILE) .

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


# NEW targets to get docker handling 201906
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
	sudo rm -fr $(abs_top_srcdir)/testing/pluto/*/OUTPUT $(abs_top_srcdir)/testing/pluto/*/NS

NSURNDIRS = $(shell mount | grep "^nsfs" | cut -d  " " -f 3)
.PHONY: nsrun
nsrun: nsrunclean
	$(if $(NSURNDIRS), $(shell sudo umount $(NSURNDIRS)), $(echo "no nsfs"))
	$(abs_top_srcdir)/testing/utils/nsrun  --ns --shutdown --log-level debug --verbos 2 --testrun

.PHONY: nsinstall
nsinstall:
	$(MAKE) clean
	$(MAKE) INITSYSTEM=docker DOCKER_PLUTONOFORK= base
	sudo $(MAKE) INITSYSTEM=docker DOCKER_PLUTONOFORK= install-base


.PHONY: nsreinstall
nsreinstall:
	$(MAKE) INITSYSTEM=docker DOCKER_PLUTONOFORK= base
	sudo $(MAKE) INITSYSTEM=docker DOCKER_PLUTONOFORK= install-base
