module gantry/cmd/hostctl

go 1.26.3

require (
	github.com/containerd/containerd/api v1.11.1 // indirect
	github.com/containerd/nerdbox v0.2.1 // indirect
	github.com/containerd/ttrpc v1.2.9 // indirect
	golang.org/x/term v0.45.0 // indirect
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af // indirect
)

require (
	github.com/containerd/log v0.1.1-0.20260403072107-cb1839ebf76b // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/grpc v1.82.1 // indirect
)

require gantry v0.0.0

replace gantry => ../..
