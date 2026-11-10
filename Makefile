# autoattest build orchestration
#
#   make build   - build the standalone ./autoattest executable
#   make dist    - build a .deb that installs it to /usr/bin/autoattest
#   make test    - run the test suite
#   make clean   - remove build artifacts

BINARY  := autoattest
PKG     := github.com/locktera/autoattest
GO      ?= go

# Version metadata. Uses the nearest git tag when there is one, otherwise the
# short commit hash. Override with e.g. `make dist VERSION=v1.2.3`.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Debian versions must start with a digit: strip a leading "v" from tags, and
# fall back to 0.0.0~git<hash> when there is no tag yet.
DEB_VERSION ?= $(shell echo '$(VERSION)' | sed -e 's/^v//' -e 's/-/~/g' -e '/^[0-9]/!s/^/0.0.0~git/')
GOARCH      ?= $(shell $(GO) env GOARCH)
DEB_ARCH    ?= $(GOARCH)
GIT_NAME    := $(shell git config user.name 2>/dev/null)
GIT_EMAIL   := $(shell git config user.email 2>/dev/null)
MAINTAINER  ?= $(or $(GIT_NAME),autoattest maintainers) <$(or $(GIT_EMAIL),root@localhost)>

# NVML (github.com/NVIDIA/go-nvml) needs cgo: it dlopen()s the NVIDIA driver's
# libnvidia-ml.so at runtime. The binary therefore links dynamically against
# glibc only; every Go dependency and the pinned CA roots are compiled in, so
# the executable is a single self-contained file.
export CGO_ENABLED := 1
# go-nvml's generated bindings reference deprecated NVML APIs; hide the noise.
export CGO_CFLAGS ?= -O2 -g -Wno-deprecated-declarations

LDFLAGS := -s -w \
	-X $(PKG)/cmd.version=$(VERSION) \
	-X $(PKG)/cmd.commit=$(COMMIT) \
	-X $(PKG)/cmd.date=$(DATE)
GOFLAGS_BUILD := -trimpath -buildvcs=false -ldflags '$(LDFLAGS)'

DIST_DIR := dist
DEB_ROOT := $(DIST_DIR)/deb
DEB_FILE := $(DIST_DIR)/$(BINARY)_$(DEB_VERSION)_$(DEB_ARCH).deb

.PHONY: all build dist test clean

all: build

build:
	GOARCH=$(GOARCH) $(GO) build $(GOFLAGS_BUILD) -o $(BINARY) .

dist: build
	rm -rf $(DEB_ROOT)
	install -d $(DEB_ROOT)/DEBIAN $(DEB_ROOT)/usr/bin
	install -m 0755 $(BINARY) $(DEB_ROOT)/usr/bin/$(BINARY)
	printf '%s\n' \
		'Package: $(BINARY)' \
		'Version: $(DEB_VERSION)' \
		'Section: utils' \
		'Priority: optional' \
		'Architecture: $(DEB_ARCH)' \
		'Depends: libc6' \
		"Installed-Size: $$(du -sk $(DEB_ROOT)/usr | cut -f1)" \
		'Maintainer: $(MAINTAINER)' \
		'Description: Intel TDX and NVIDIA GPU confidential computing attestation' \
		' autoattest checks that an Intel TDX confidential VM and its attached' \
		' NVIDIA GPUs are running under Confidential Compute protection, and' \
		' prints a single SAFE / NOT SAFE verdict.' \
		> $(DEB_ROOT)/DEBIAN/control
	dpkg-deb --root-owner-group --build $(DEB_ROOT) $(DEB_FILE)
	@echo "Built $(DEB_FILE)"

test:
	$(GO) test ./...

clean:
	rm -f $(BINARY)
	rm -rf $(DIST_DIR)
