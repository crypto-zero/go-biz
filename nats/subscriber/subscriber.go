package subscriber

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/nats-io/jsm.go"
	"github.com/nats-io/nats.go"
)

const (
	// defaultAckWait the consumer ack wait
	defaultAckWait = 10 * time.Second
	// defaultMaxDeliverAttempts the consumer max deliver attempts
	defaultMaxDeliverAttempts = 400
	// defaultMaxWaiting is the default max waiting
	defaultMaxWaiting = 1
	// defaultMaxAckPending is the default max pending
	defaultMaxAckPending = 1
	// jitterMillis the consumer jitter millis
	jitterMillis = 100
)

type DeliverOption int

const (
	DeliverOptionUnspecified DeliverOption = iota
	DeliverOptionAllAvailable
	DeliverOptionLastPerSubject
)

func (o DeliverOption) option() jsm.ConsumerOption {
	switch o {
	case DeliverOptionLastPerSubject:
		return jsm.DeliverLastPerSubject()
	default:
		return jsm.DeliverAllAvailable()
	}
}

type JetStreamSubscriberOptions struct {
	ConsumerPrefix     string
	StreamName         string
	AckWait            time.Duration
	MaxDeliverAttempts int
	MaxWaiting         uint
	MaxAckPending      uint
	DeliverOption      DeliverOption
}

func (o *JetStreamSubscriberOptions) applyDefaultValue() {
	if o.AckWait == 0 {
		o.AckWait = defaultAckWait
	}

	if o.MaxDeliverAttempts == 0 {
		o.MaxDeliverAttempts = defaultMaxDeliverAttempts
	}
	if o.MaxWaiting == 0 {
		o.MaxWaiting = defaultMaxWaiting
	}
	if o.MaxAckPending == 0 {
		o.MaxAckPending = defaultMaxAckPending
	}
}

type JetStreamSubscriber struct {
	conn    *nats.Conn
	options JetStreamSubscriberOptions
	logger  *slog.Logger
}

type Handler interface {
	Handle(ctx context.Context, subject, id string, data []byte, inProgress func(ctx context.Context) error) error
}

type HandlerFunc func(ctx context.Context, subject, id string, data []byte,
	inProgress func(ctx context.Context) error) error

func (f HandlerFunc) Handle(ctx context.Context, subject, id string, data []byte,
	inProgress func(ctx context.Context) error) error {
	return f(ctx, subject, id, data, inProgress)
}

func (s *JetStreamSubscriber) Subscribe(ctx context.Context, subject, consumer string, handler Handler,
	subOpts ...nats.SubOpt,
) error {
	var err error
	consumer, err = s.initialConsumer(consumer)
	if err != nil {
		return err
	}
	jsc, err := s.conn.JetStream()
	if err != nil {
		return fmt.Errorf("failed to create jetstream context: %w", err)
	}
	subscription, err := jsc.PullSubscribe(subject, consumer, subOpts...)
	if err != nil {
		return fmt.Errorf("failed to pull subcription: %w", err)
	}

	defer func(subscription *nats.Subscription) {
		err = subscription.Unsubscribe()
		if err != nil {
			s.logger.ErrorContext(ctx, "failed to unsubscribe from jetstream", "err", err)
		}
	}(subscription)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err = s.fetchMessage(ctx, subscription, handler); err != nil {
				return err
			}
		}
	}
}

func (s *JetStreamSubscriber) fetchMessage(ctx context.Context, subscription *nats.Subscription,
	handler Handler,
) error {
	messages, err := subscription.Fetch(1)
	if errors.Is(err, nats.ErrConsumerLeadershipChanged) {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.jitterDuration()):
		}
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, nats.ErrTimeout) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("fetch message failed: %w", err)
	}
	if len(messages) == 0 {
		return nil
	}
	msg := messages[0]
	err = handler.Handle(ctx, msg.Subject, msg.Header.Get(nats.MsgIdHdr), msg.Data, func(ctx context.Context) error {
		return msg.InProgress(nats.Context(ctx))
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to handle message", "err", err)
		return nil
	}
	if err := msg.Ack(nats.Context(ctx)); err != nil {
		s.logger.ErrorContext(ctx, "failed to ack message", "err", err)
		return nil
	}
	return nil
}

func (s *JetStreamSubscriber) initialConsumer(consumer string) (string, error) {
	consumerName := s.options.ConsumerPrefix + consumer
	manager, err := jsm.New(s.conn)
	if err != nil {
		return "", fmt.Errorf("failed to create jet stream manager: %w", err)
	}
	consumerConfig := jsm.DefaultConsumer
	_, err = manager.LoadOrNewConsumerFromDefault(
		s.options.StreamName,
		consumerName,
		consumerConfig,
		jsm.DurableName(consumerName),
		jsm.AcknowledgeExplicit(),
		jsm.AckWait(s.options.AckWait),
		jsm.MaxAckPending(s.options.MaxAckPending),
		s.options.DeliverOption.option(),
		jsm.MaxDeliveryAttempts(s.options.MaxDeliverAttempts),
		jsm.ReplayInstantly(),
		jsm.MaxWaiting(s.options.MaxWaiting),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create jetstream consumer: %w", err)
	}
	return consumerName, nil
}

func (s *JetStreamSubscriber) jitterDuration() time.Duration {
	duration := jitterMillis + rand.IntN(jitterMillis)
	return time.Duration(duration) * time.Millisecond
}

// NewJetStreamSubscriber create a new jetstream subscriber
func NewJetStreamSubscriber(conn *nats.Conn, options JetStreamSubscriberOptions,
	logger *slog.Logger,
) *JetStreamSubscriber {
	options.applyDefaultValue()
	return &JetStreamSubscriber{
		conn:    conn,
		options: options,
		logger:  logger,
	}
}
