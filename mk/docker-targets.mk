# docker make/start/stop targets, for Libreswan testing
#
# Copyright (C) 2016-2017 Antony Antony <antony@phenome.org>
# 
# make DISTRO=fedora DISTRO_REL=27 docker-image

# These variable could be changed
#
DOCKER_CMD ?= sudo docker
D ?= testing/docker

W1 = $(firstword $(subst -, ,$1))
W2 = $(or $(word 2, $(subst -, ,$1)), $(value 2))
W3 = $(or $(word 3, $(subst -, ,$1)), $(value 2))

FIRST_TARGET ?=$@	# keep track of original target
DISTRO ?= fedora	# default distro
DISTRO_REL ?= 27 	# default release

DI_T ?= swanbase 	#docker image tag

# for travis
TRAVIS=$(call W1, $(FIRST_TARGET))
ifeq ($(TRAVIS), travis)
	BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
	DISTRO =  $(call W2, $(BRANCH), '')
	DISTRO_REL = $(call W3, $(BRANCH), '')
	$(call DISTRO=$(DISTRO) DISTRO_REL=$(DISTRO_REL) docker-image)
endif

# end of configurable variables 

DI = $(DISTRO)-$(DISTRO_REL)
DOCKER_BASE = $(DI)-base
DOCKER_PACKAGES = $(DI)-packages
DOCKER_SSH = $(DI)-ssh
DOCKER_START = $(DI)-start
DOCKERFILE ?= $(D)/dockerfile
DOCKERFILE_PKG = $(D)/Dockerfile-$(DISTRO)-min-packages

ifeq ($(DISTRO), ubuntu)
		DOCKERFILE_PKG=$(D)/Dockerfile-debian-min-packages
endif

.PHONY: dcokerfile-debian-cmd
dcokerfile-debian-min:
	$call(sed -i   's#CMD.*#CMD ["/lib/systemd/systemd"]#' testing/docker/dockerfile)

dcokerfile-ubuntu-min:
	$call(sed -i   's#CMD.*#CMD ["/sbin/init"]#' testing/docker/dockerfile)

.PHONY: dcokerfile
dockerfile: $(DOCKERFILE_BASE) $(DOCKERFILE_PKG)
	echo "FROM $(DISTRO):$(DISTRO_REL) " >  $(DOCKERFILE)
	echo "ENV container docker"  >> $(DOCKERFILE)
	echo 'MAINTAINER "Antony Antony" <antony@phenome.org>' >> $(DOCKERFILE)
	cat $(DOCKERFILE_BASE)  $(DOCKERFILE_PKG) >> $(DOCKERFILE)
	$(call make dockerfile-$(DISTRO)-cmd)

.PHONY docker-image:
docker-image: $(DI)

.PHONY travis-docker-image:
travis-image:
	$(MAKE) $(BRANCH)

.PHONY: travis-ubuntu-xenial
travis-ubuntu-xenial: ubuntu-xenial-packages
	$(DOCKER_CMD) run -h $(DI_T) --privileged --name $(DI_T) \
	-v $(PWD):/home/build/libreswan  \
	-v /sys/fs/cgroup:/sys/fs/cgroup:ro -d ubuntu-xenial-packages
	$(DOCKER_CMD) ps -a

$(DOCKER_SSH): DOCKERFILE_SSH = $(D)/Dockerfile-swan-ssh
$(DOCKER_SSH): dcokerfile $(DOCKERFILE_SSH)
	@echo "make $@" 
	cat $(DOCKERFILE_SSH) >>  $(DOCKERFILE)
	$(DOCKER_CMD) build -t $(DI_T) -f $(DOCKERFILE) .

.PHONY: $(DI)
$(DI): dockerfile $(DOCKER_SSH)
$(DI):
	@echo "DISTRO $(DISTRO) $(DISTRO_REL)"
	@echo "make $@"

.PHONY: docker-start
docker-start:
	$(DOCKER_CMD) run -h $(DI_T) --privileged --name $(DI_T) \
	-v /home/build/libreswan:/home/build/libreswan  \
	-v /sys/fs/cgroup:/sys/fs/cgroup:ro -d $(DI_T)

.PHONY: docker-stop
docker-stop:
	$(DOCKER_CMD) stop $(DI_T)
	$(DOCKER_CMD) rm $(DI_T)
