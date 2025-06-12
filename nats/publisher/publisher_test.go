package publisher

import (
	"context"
	"testing"

	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

func TestPublisher(t *testing.T) {
	opt := natsserver.DefaultTestOptions
	opt.Port = -1
	opt.JetStream = true
	srv := natsserver.RunServer(&opt)

	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()

	pub, err := NewJetStreamPublisher(nc, JetStreamPublisherOptions{
		StreamName:           "TEST",
		SubjectPattern:       "TEST.*",
		RepublishSource:      "TEST.*",
		RepublishDestination: "TEST_REALTIME.{{wildcard(1)}}",
		StreamReplicasSize:   1,
		StreamMaxAge:         0,
		StreamMaxBytes:       0,
	})
	if err != nil {
		t.Error(err)
		return
	}
	if err = pub.Publish(context.Background(), "TEST.1", "123", []byte("hello world")); err != nil {
		t.Error(err)
	}
}
