package subscriber

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/nats-io/jsm.go"
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

	m, err := jsm.New(nc)
	if err != nil {
		t.Error(err)
		return
	}
	_, err = m.NewStream("HELLO", jsm.Subjects("HELLO.*"))
	if err != nil {
		t.Error(err)
		return
	}

	var message = "hello world"
	var subject = "HELLO.1"
	err = nc.Publish(subject, []byte(message))
	if err != nil {
		t.Error(err)
		return
	}

	sub := NewJetStreamSubscriber(nc, JetStreamSubscriberOptions{
		ConsumerPrefix: "SUB_",
		StreamName:     "HELLO",
	}, slog.Default().With("subscriber", "test"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ch := make(chan []byte, 1)
	go sub.Subscribe(ctx, "HELLO.1", "TEST", HandlerFunc(func(ctx context.Context, subject, id string,
		data []byte, inProgress func(ctx context.Context) error) error {
		ch <- data
		return nil
	}))
	select {
	case <-ctx.Done():
		t.Error(ctx.Err())
	case data := <-ch:
		if string(data) != message {
			t.Fail()
		}
	}
}

func TestSubscribeContext(t *testing.T) {
	opt := natsserver.DefaultTestOptions
	opt.Port = -1
	opt.JetStream = true
	srv := natsserver.RunServer(&opt)

	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	{
		sub := NewJetStreamSubscriber(nc, JetStreamSubscriberOptions{
			ConsumerPrefix: "SUB_",
			StreamName:     "HELLO",
		}, slog.Default().With("subscriber", "test"))

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err = sub.Subscribe(ctx, "HELLO.1", "TEST", HandlerFunc(func(ctx context.Context,
			subject, id string, data []byte, inProgress func(ctx context.Context) error) error {
			return nil
		}))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fail()
		}
	}

	{
		sub := NewJetStreamSubscriber(nc, JetStreamSubscriberOptions{
			ConsumerPrefix: "SUB_",
			StreamName:     "HELLO",
		}, slog.Default().With("subscriber", "test"))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = sub.Subscribe(ctx, "HELLO.1", "TEST", HandlerFunc(func(ctx context.Context,
			subject, id string, data []byte, inProgress func(ctx context.Context) error) error {
			return nil
		}))
		if !errors.Is(err, context.Canceled) {
			t.Fail()
		}
	}
}
