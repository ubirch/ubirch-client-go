EXECUTABLE=ubirch-go-client

# we are building for ARM Linux
GOOS=linux
CGO=0

VERSION=`git describe --tags`
BUILD=`date +%Y%m%d%H%M%S`

LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Build=${BUILD}"

arm:
	cd main; GOOS=${GOOS} CGO_ENABLED=${CGO} GOARCH=arm64 go build ${LDFLAGS} -o ${EXECUTABLE} main

x86:
	cd main; GOOS=${GOOS} CGO_ENABLED=${CGO} GOARCH=amd64 go build ${LDFLAGS} -o ${EXECUTABLE} main

clean:
	rm -f main/${EXECUTABLE}

.PHONY: clean arm x86
