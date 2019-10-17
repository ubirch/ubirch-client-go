EXECUTABLE=ubirch-go-client

# we are building for ARM Linux
GOOS=linux
CGO=0
GOARCH=arm

VERSION=`git describe --tags`
BUILD=`date +%Y%m%d%H%M%S`

LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Build=${BUILD}"

build:
	cd main; GOOS=${GOOS} CGO_ENABLED=${CGO} GOARCH=${GOARCH} go build ${LDFLAGS} -o ${EXECUTABLE} main

install:
	cd main; go install ${LDFLAGS} main

clean:
	rm -f main/${EXECUTABLE}

.PHONY: clean install