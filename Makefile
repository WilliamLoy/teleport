ETCD_NODE1 := http://127.0.0.1:4001
ETCD_NODES := ${ETCD_NODE1}
ETCD_FLAGS := TELEPORT_TEST_ETCD_NODES=${ETCD_NODES}
TELEPORT_DEBUG_TESTS ?= no
OUT := out
GO15VENDOREXPERIMENT := 1
PKGPATH=github.com/gravitational/teleport
export

.PHONY: install test test-with-etcd remove-temp files test-package update test-grep-package cover-package cover-package-with-etcd run profile sloccount set-etcd install-assets docs-serve

#
# Default target: builds all 3 executables and plaaces them in a current directory
#
.PHONY: all
all: teleport tctl tsh

.PHONY: tctl
tctl: 
	go build -o $(OUT)/tctl $(BUILDFLAGS) -i $(PKGPATH)/tool/tctl

.PHONY: teleport
teleport: 
	go build -o $(OUT)/teleport $(BUILDFLAGS) -i $(PKGPATH)/tool/teleport

.PHONY: tsh
tsh: 
	go build -o $(OUT)/tsh $(BUILDFLAGS) -i $(PKGPATH)/tool/tsh

install: remove-temp-files flags
	go install -ldflags $(TELEPORT_LINKFLAGS) $(PKGPATH)/tool/teleport \
	           $(PKGPATH)/tool/tctl \
	           $(PKGPATH)/tool/tsh \

clean:
	rm -rf $(OUT)

#
# tests everything: called by Jenkins
#
test: FLAGS ?= -cover
test: 
	go test -v $(PKGPATH)/tool/tsh/... \
			   $(PKGPATH)/lib/... \
			   $(PKGPATH)/tool/teleport... $(FLAGS)
	go vet ./tool/... ./lib/...

flags:
	go install $(PKGPATH)/vendor/github.com/gravitational/version/cmd/linkflags
	$(eval TELEPORT_LINKFLAGS := "$(shell linkflags -pkg=$(PWD) -verpkg=$(PKGPATH)/vendor/github.com/gravitational/version)")


test-with-etcd: install
	${ETCD_FLAGS} go test -v -test.parallel=0 $(shell go list ./... | grep -v /vendor/) -cover

remove-temp-files:
	find . -name flymake_* -delete

test-package: remove-temp-files install
	go test -v -test.parallel=0 ./$(p)

test-package-with-etcd: remove-temp-files install
	${ETCD_FLAGS} go test -v -test.parallel=0 ./$(p)

test-grep-package-with-etcd: remove-temp-files install
	${ETCD_FLAGS} go test -v -test.parallel=0 ./$(p) -check.f=$(e)


test-grep-package: remove-temp-files install
	go test -v ./$(p) -check.f=$(e)

cover-package: remove-temp-files
	go test -v ./$(p)  -coverprofile=/tmp/coverage.out
	go tool cover -html=/tmp/coverage.out

cover-package-with-etcd: remove-temp-files
	${ETCD_FLAGS} go test -v ./$(p)  -coverprofile=/tmp/coverage.out
	go tool cover -html=/tmp/coverage.out

profile:
	go tool pprof http://localhost:6060/debug/pprof/profile

sloccount:
	find . -path ./vendor -prune -o -name "*.go" -print0 | xargs -0 wc -l
