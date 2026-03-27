TAG := $(shell git describe --tags --always --dirty)
CONTAINER_REPO ?= ghcr.io/aruiz14/top-tcp-avg
IMAGE_TAG ?= $(TAG)
CLANG_FORMAT ?= clang-format
IG_VERSION ?= v0.50.1
GOARCH ?= $(shell docker version --format='{{.Server.Arch}}')

.PHONY: build
build:
	mkdir -p build
	docker run --rm -v $(PWD):/ws -w /ws ghcr.io/inspektor-gadget/gadget-builder:$(IG_VERSION) \
		sh -c 'wget https://github.com/inspektor-gadget/inspektor-gadget/releases/download/$(IG_VERSION)/ig-linux-$(GOARCH)-$(IG_VERSION).tar.gz -qO- | tar zx -C /usr/local/bin ig && \
		ig image build --local --tag $(CONTAINER_REPO):$(IMAGE_TAG) --validate-metadata . && \
		ig image export $(CONTAINER_REPO):$(IMAGE_TAG) build/image.tar'

.PHONY: push
push: build
	docker run --rm -v ig:/var/lib/ig -v $(PWD):/ws -w /ws ghcr.io/inspektor-gadget/ig:$(IG_VERSION) image import build/image.tar
	docker run --rm -v ig:/var/lib/ig -v $(PWD):/ws -v $$HOME/.docker/config.json:/root/.docker/config.json -w /ws ghcr.io/inspektor-gadget/ig:$(IG_VERSION) image push $(CONTAINER_REPO):$(IMAGE_TAG)

.PHONY: clang-format
clang-format:
	$(CLANG_FORMAT) -i program.bpf.c
