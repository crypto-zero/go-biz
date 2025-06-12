package publisher

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/jsm.go"
	"github.com/nats-io/jsm.go/api"
	"github.com/nats-io/nats.go"
)

const (
	// defaultStreamReplicasSize is the size of the Nats stream replicas.
	defaultStreamReplicasSize = 3
	// streamMaxAge is the max age of the Nats stream.
	defaultStreamMaxAge = 3 * 31 * 24 * time.Hour // equivalent to 3 months.
	// defaultStreamMaxBytes the max bytes of the nats stream. equivalent to 20GB
	defaultStreamMaxBytes = 20 * 1 << 30
)

type JetStreamPublisherOptions struct {
	StreamName           string
	SubjectPattern       string
	RepublishSource      string
	RepublishDestination string
	StreamReplicasSize   int
	StreamMaxAge         time.Duration
	StreamMaxBytes       int64
}

func (o *JetStreamPublisherOptions) applyDefaultValue() {
	if o.StreamReplicasSize == 0 {
		o.StreamReplicasSize = defaultStreamReplicasSize
	}
	if o.StreamMaxAge == 0 {
		o.StreamMaxAge = defaultStreamMaxAge
	}
	if o.StreamMaxBytes == 0 {
		o.StreamMaxBytes = defaultStreamMaxBytes
	}
}

type JetStreamPublisher struct {
	conn *nats.Conn
}

func (c *JetStreamPublisher) Publish(_ context.Context, subject string, msgID string, data []byte) error {
	msg := nats.NewMsg(subject)
	msg.Header.Add(nats.MsgIdHdr, msgID)
	msg.Data = data
	if err := c.conn.PublishMsg(msg); err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}
	return nil
}

func (c *JetStreamPublisher) setup(opt JetStreamPublisherOptions) error {
	if c.conn == nil {
		return fmt.Errorf("nats conn is not set")
	}
	manager, err := jsm.New(c.conn)
	if err != nil {
		return fmt.Errorf("create jetstream manager failed: %w", err)
	}
	_, err = manager.LoadOrNewStream(
		opt.StreamName,
		jsm.FileStorage(),
		jsm.Subjects(opt.SubjectPattern),
		jsm.NoAck(), // require by jsm.ErrAckStreamIngestsAll
		jsm.Replicas(opt.StreamReplicasSize),
		jsm.LimitsRetention(),
		jsm.MaxAge(opt.StreamMaxAge),
		jsm.MaxBytes(opt.StreamMaxBytes),
		jsm.DiscardOld(),
		jsm.AllowRollup(),
		jsm.AllowDirect(),
		jsm.Republish(
			&api.RePublish{
				Source:      opt.RepublishSource,
				Destination: opt.RepublishDestination,
				HeadersOnly: false,
			},
		),
		jsm.Compression(api.S2Compression),
	)
	if err != nil {
		return fmt.Errorf("failed to create jetstream: %w", err)
	}
	return nil
}

func NewJetStreamPublisher(conn *nats.Conn, opt JetStreamPublisherOptions) (*JetStreamPublisher, error) {
	pub := &JetStreamPublisher{
		conn: conn,
	}
	opt.applyDefaultValue()
	if err := pub.setup(opt); err != nil {
		return nil, err
	}
	return pub, nil
}

type Message interface {
	ID() string
	Subject() string
	Body() ([]byte, error)
}

type JetStreamMessagePublisher struct {
	*JetStreamPublisher
}

func (p *JetStreamMessagePublisher) Publish(ctx context.Context, msg Message) error {
	body, err := msg.Body()
	if err != nil {
		return fmt.Errorf("failed to get message body: %w", err)
	}
	return p.JetStreamPublisher.Publish(ctx, msg.Subject(), msg.ID(), body)
}

func NewJetStreamMessagePublisher(conn *nats.Conn, opt JetStreamPublisherOptions) (*JetStreamMessagePublisher, error) {
	pub, err := NewJetStreamPublisher(conn, opt)
	if err != nil {
		return nil, err
	}
	return &JetStreamMessagePublisher{JetStreamPublisher: pub}, nil
}
