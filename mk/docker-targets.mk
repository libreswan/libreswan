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

.PHONY: travis-docker-image
travis-docker-image: BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
travis-docker-image: DISTRO =  $(call W2, $(BRANCH),fedora)
travis-docker-image: DISTRO_REL = $(call W3, $(BRANCH),27)
travis-docker-image:
	$(MAKE) DISTRO=$(DISTRO) DISTRO_REL=$(DISTRO_REL) docker-image

# end of configurable variables 

DI = $(DISTRO)-$(DISTRO_REL)
DOCKER_BASE = $(DI)-base
DOCKER_PACKAGES = $(DI)-packages
DOCKER_SSH = $(DI)-ssh
DOCKER_START = $(DI)-start
DOCKERFILE ?= $(D)/dockerfile
DOCKERFILE_PKG = $(D)/Dockerfile-$(DISTRO)-min-packages
CMD_CHANGE=

ifeq ($(DISTRO), ubuntu)
	DOCKERFILE_PKG=$(D)/Dockerfile-debian-min-packages
	CMD_CHANGE = dcokerfile-ubuntu-cmd
endif

ifeq ($(DISTRO), debian)
	DOCKERFILE_PKG=$(D)/Dockerfile-debian-min-packages
	CMD_CHANGE = dcokerfile-debian-cmd
endif

.PHONY: dcokerfile-debian-cmd
dcokerfile-debian-min:
	$(shell sed -i 's#CMD.*#CMD ["/lib/systemd/systemd"]#' testing/docker/dockerfile)

.PHONY: dcokerfile-ubuntu-cmd
dcokerfile-ubuntu-cmd:
	$(shell sed -i 's#CMD.*#CMD ["/sbin/init"]#' testing/docker/dockerfile)

.PHONY: dcokerfile
dockerfile: $(DOCKERFILE_PKG)
	echo "FROM $(DISTRO):$(DISTRO_REL)" > $(DOCKERFILE)
	echo "ENV container docker" >> $(DOCKERFILE)
	echo 'MAINTAINER "Antony Antony" <antony@phenome.org>' >> $(DOCKERFILE)
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
docker-ssh-image: dcokerfile $(CMD_CHANGE) docker-build
	cat $(DOCKERFILE_SSH) >> $(DOCKERFILE)

.PHONY: docker-min-image
docker-min-image: dockerfile $(CMD_CHANGE) docker-build
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
