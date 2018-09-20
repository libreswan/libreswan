# docker make/start/stop targets, for Libreswan testing
#
# Copyright (C) 2016-2017 Antony Antony <antony@phenome.org>
# 
# make DISTRO=fedora DISTRO_REL=28 docker-image

# These variable could be changed
#
DOCKER_CMD ?= sudo docker
D ?= testing/docker

W1 = $(firstword $(subst -, ,$1))
W2 = $(or $(word 2, $(subst -, ,$1)), $(value 2))
W3 = $(or $(word 3, $(subst -, ,$1)), $(value 2))

FIRST_TARGET ?=$@	# keep track of original target
DISTRO ?= fedora	# default distro
DISTRO_REL ?= 28 	# default release

DI_T ?= swanbase 	#docker image tag

# end of configurable variables 

DI = $(DISTRO)-$(DISTRO_REL)
DOCKER_BASE = $(DI)-base
DOCKER_PACKAGES = $(DI)-packages
DOCKER_SSH = $(DI)-ssh
DOCKER_START = $(DI)-start
DOCKERFILE ?= $(D)/dockerfile
DOCKERFILE_PKG = $(D)/Dockerfile-$(DISTRO)-min-packages
TWEAKS=

#
# Distribution specific tweaks
#
ifeq ($(DISTRO), ubuntu)
	DOCKERFILE_PKG=$(D)/Dockerfile-debian-min-packages
	TWEAKS = dcokerfile-ubuntu-cmd
	ifeq ($(DISTRO_REL), xenial)
		TWEAKS = flip-glibc-kern-headers
	endif
endif

ifeq ($(DISTRO), debian)
	DOCKERFILE_PKG=$(D)/Dockerfile-debian-min-packages
	TWEAKS = dcokerfile-debian-cmd
endif

ifeq ($(DISTRO), centos)
	ifeq ($(DISTRO_REL), 7)
		TWEAKS = disable-dsnssec
	endif
	ifeq ($(DISTRO_REL), 6)
		TWEAKS = disable-dsnssec
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


.PHONY: dcokerfile-remove-libreswan-spec
dcokerfile-remove-libreswan-spec:
	$(shell sed -i '/libreswan\.spec/d' testing/docker/dockerfile)

.PHONY: dcokerfile-debian-cmd
dcokerfile-debian-cmd:
	$(shell sed -i 's#CMD.*#CMD ["/lib/systemd/systemd"]#' testing/docker/dockerfile)

.PHONY: dcokerfile-ubuntu-cmd
dcokerfile-ubuntu-cmd:
	$(shell sed -i 's#CMD.*#CMD ["/sbin/init"]#' testing/docker/dockerfile)

.PHONY: disable-dsnssec
disable-dsnssec:
	$(shell (grep "^USE_DNSSEC=" Makefile.inc.local || echo "USE_DNSSEC=false" >> Makefile.inc.local))

.PHONY: disable-seccomp
disable-seccomp:
	$(shell (grep "^USE_SECCOMP=" Makefile.inc.local || echo "USE_SECCOMP=false" >> Makefile.inc.local))

.PHONY: flip-glibc-kern-headers
flip-glibc-kern-headers:
	$(shell (grep "^USE_GLIBC_KERN_FLIP_HEADERS=" Makefile.inc.local || echo "USE_GLIBC_KERN_FLIP_HEADERS=true" >> Makefile.inc.local))

#
# end  of Distribution tweaks
#

.PHONY: travis-docker-image
travis-docker-image:
	$(MAKE) DISTRO=$(DISTRO) DISTRO_REL=$(DISTRO_REL) docker-image

define debian_exp_repo
	if [ $(1) == "experimental" ] ; then \
		echo 'RUN echo "deb http://deb.debian.org/debian experimental main" >> /etc/apt/sources.list.d/experimental.list' >> $(2);\
	fi
endef

.PHONY: dcokerfile
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
docker-build: dcokerfile
	$(DOCKER_CMD) build -t $(DI_T) -f $(DOCKERFILE) .

.PHONY: docker-ssh-image
docker-ssh-image: DOCKERFILE_SSH = $(D)/Dockerfile-swan-ssh
docker-ssh-image: dcokerfile $(TWEAKS) docker-build
	cat $(DOCKERFILE_SSH) >> $(DOCKERFILE)

.PHONY: docker-min-image
docker-min-image: dockerfile $(TWEAKS) docker-build
	echo "done docker image tag $(DI_T) from $(DISTRO)-$(DISTRO_REL)"

.PHONY: docker-image
docker-image: dockerfile docker-ssh-image docker-build
	echo "done docker image tag $(DI_T) from $(DISTRO)-$(DISTRO_REL) with ssh"

.PHONY: docker-start
docker-start:
	$(DOCKER_CMD) run -h $(DI_T) --privileged --name $(DI_T) \
	-v /home/build/libreswan:/home/build/libreswan  \
	-v /sys/fs/cgroup:/sys/fs/cgroup:ro -d $(DI_T)

.PHONY: docker-stop
docker-stop:
	$(DOCKER_CMD) stop $(DI_T)
	$(DOCKER_CMD) rm $(DI_T)
