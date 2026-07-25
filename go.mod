module gantry

go 1.26.3

require (
	github.com/containerd/containerd/api v1.11.1
	github.com/containerd/nerdbox v0.2.1
	github.com/containerd/ttrpc v1.2.9
	github.com/ebitengine/purego v0.10.2
	github.com/hanwen/go-fuse/v2 v2.11.0
	golang.org/x/term v0.43.0
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af
)

require (
	github.com/containerd/log v0.1.1-0.20260403072107-cb1839ebf76b // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/grpc v1.82.1 // indirect
)

replace github.com/hanwen/go-fuse/v2 => ./third_party/go-fuse
