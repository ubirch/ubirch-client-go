EXECUTABLE=ubirch-client

GOOS=linux
CGO=0
DOCKER_IMAGE=ubirch/ubirch-client
VERSION=`git describe --tags`
BUILD=`date +%Y%m%d%H%M%S`

LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Build=${BUILD}"

x86:
	cd main; GOOS=${GOOS} CGO_ENABLED=${CGO} GOARCH=amd64 go build ${LDFLAGS} -o ${EXECUTABLE} main

arm:
	cd main; GOOS=${GOOS} CGO_ENABLED=${CGO} GOARCH=arm64 go build ${LDFLAGS} -o ${EXECUTABLE} main

docker.x86:
	docker build --build-arg GOARCH=amd64 -t $(DOCKER_IMAGE) .

docker.arm:
	docker build --build-arg GOARCH=arm64 -t $(DOCKER_IMAGE):arm .

clean:
	rm -f main/${EXECUTABLE}

.PHONY: clean arm x86 docker.x86 docker.arm
