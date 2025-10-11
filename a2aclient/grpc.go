
// Copyright 2025 The A2A Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package a2aclient

import (
	"context"
	"fmt"
	"iter"

	"github.com/a2aproject/a2a-go/a2a"
	"github.com/a2aproject/a2a-go/a2apb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

// WithGRPCTransport returns a Client factory configuration option that if applied will
// enable support of gRPC-A2A communication.
func WithGRPCTransport(opts ...grpc.DialOption) FactoryOption {
	return WithTransport(
		a2a.TransportProtocolGRPC,
		TransportFactoryFn(func(ctx context.Context, url string, card *a2a.AgentCard) (Transport, error) {
			conn, err := grpc.NewClient(url, opts...)
			if err != nil {
				return nil, err
			}
			return NewGRPCTransport(conn), nil
		}),
	)
}

// NewGRPCTransport exposes a method for direct A2A gRPC protocol handler.
func NewGRPCTransport(conn *grpc.ClientConn) Transport {
	return &grpcTransport{
		client:      a2apb.NewA2AServiceClient(conn),
		closeConnFn: func() error { return conn.Close() },
	}
}

// grpcTransport implements Transport by delegating to a2apb.A2AServiceClient.
type grpcTransport struct {
	client      a2apb.A2AServiceClient
	closeConnFn func() error
}

func (c *grpcTransport) SendMessage(ctx context.Context, message *a2a.MessageSendParams) (a2a.SendMessageResult, error) {
	pMsg, err := toProtoMessage(message.Message)
	if err != nil {
		return nil, err
	}

	req := &a2apb.SendMessageRequest{
		Request: pMsg,
	}

	resp, err := c.client.SendMessage(ctx, req)
	if err != nil {
		return nil, err
	}

	switch r := resp.Payload.(type) {
	case *a2apb.SendMessageResponse_Msg:
		return fromProtoMessage(r.Msg)
	case *a2apb.SendMessageResponse_Task:
		return fromProtoTask(r.Task)
	default:
		return nil, fmt.Errorf("unsupported SendMessageResponse type: %T", r)
	}
}

// A2A protocol methods

func (c *grpcTransport) GetTask(ctx context.Context, query *a2a.TaskQueryParams) (*a2a.Task, error) {
	return &a2a.Task{}, ErrNotImplemented
}

func (c *grpcTransport) CancelTask(ctx context.Context, id *a2a.TaskIDParams) (*a2a.Task, error) {
	return &a2a.Task{}, ErrNotImplemented
}

func (c *grpcTransport) ResubscribeToTask(ctx context.Context, id *a2a.TaskIDParams) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		yield(&a2a.Message{}, ErrNotImplemented)
	}
}

func (c *grpcTransport) SendStreamingMessage(ctx context.Context, message *a2a.MessageSendParams) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
	}
}

func (c *grpcTransport) GetTaskPushConfig(ctx context.Context, params *a2a.GetTaskPushConfigParams) (*a2a.TaskPushConfig, error) {
	return &a2a.TaskPushConfig{}, ErrNotImplemented
}

func (c *grpcTransport) ListTaskPushConfig(ctx context.Context, params *a2a.ListTaskPushConfigParams) ([]*a2a.TaskPushConfig, error) {
	return []*a2a.TaskPushConfig{}, ErrNotImplemented
}

func (c *grpcTransport) SetTaskPushConfig(ctx context.Context, params *a2a.TaskPushConfig) (*a2a.TaskPushConfig, error) {
	return &a2a.TaskPushConfig{}, ErrNotImplemented
}

func (c *grpcTransport) DeleteTaskPushConfig(ctx context.Context, params *a2a.DeleteTaskPushConfigParams) error {
	return ErrNotImplemented
}

func (c *grpcTransport) GetAgentCard(ctx context.Context) (*a2a.AgentCard, error) {
	return &a2a.AgentCard{}, ErrNotImplemented
}

func (c *grpcTransport) Destroy() error {
	return c.closeConnFn()
}

// Conversion functions copied from pbconv

func toProtoMessage(msg *a2a.Message) (*a2apb.Message, error) {
	if msg == nil {
		return nil, fmt.Errorf("message is nil")
	}
	parts := make([]*a2apb.Part, len(msg.Parts))
	for i, p := range msg.Parts {
		part, err := toProtoPart(p)
		if err != nil {
			return nil, fmt.Errorf("failed to convert part: %w", err)
		}
		parts[i] = part
	}

	var pMetadata *structpb.Struct
	if msg.Metadata != nil {
		s, err := structpb.NewStruct(msg.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to convert metadata to proto struct: %w", err)
		}
		pMetadata = s
	}

	return &a2apb.Message{
		MessageId:  msg.ID,
		ContextId:  msg.ContextID,
		Extensions: msg.Extensions,
		Content:    parts,
		Role:       toProtoRole(msg.Role),
		TaskId:     string(msg.TaskID),
		Metadata:   pMetadata,
	}, nil
}

func toProtoPart(part a2a.Part) (*a2apb.Part, error) {
	switch p := part.(type) {
	case *a2a.TextPart:
		return &a2apb.Part{Part: &a2apb.Part_Text{Text: p.Text}}, nil
	default:
		return nil, fmt.Errorf("unsupported part type: %T", p)
	}
}

func toProtoRole(role a2a.MessageRole) a2apb.Role {
	switch role {
	case a2a.MessageRoleUser:
		return a2apb.Role_ROLE_USER
	case a2a.MessageRoleAgent:
		return a2apb.Role_ROLE_AGENT
	default:
		return a2apb.Role_ROLE_UNSPECIFIED
	}
}

func fromProtoMessage(pMsg *a2apb.Message) (*a2a.Message, error) {
	if pMsg == nil {
		return nil, fmt.Errorf("proto message is nil")
	}
	parts := make([]a2a.Part, len(pMsg.GetContent()))
	for i, p := range pMsg.GetContent() {
		part, err := fromProtoPart(p)
		if err != nil {
			return nil, fmt.Errorf("failed to convert part: %w", err)
		}
		parts[i] = part
	}
	msg := &a2a.Message{
		ID:         pMsg.GetMessageId(),
		ContextID:  pMsg.GetContextId(),
		Extensions: pMsg.GetExtensions(),
		Parts:      parts,
		Role:       fromProtoRole(pMsg.GetRole()),
		TaskID:     a2a.TaskID(pMsg.GetTaskId()),
	}
	if pMsg.GetMetadata() != nil {
		msg.Metadata = pMsg.GetMetadata().AsMap()
	}
	return msg, nil
}

func fromProtoPart(p *a2apb.Part) (a2a.Part, error) {
	switch part := p.GetPart().(type) {
	case *a2apb.Part_Text:
		return &a2a.TextPart{Text: part.Text}, nil
	default:
		return nil, fmt.Errorf("unsupported part type: %T", part)
	}
}

func fromProtoRole(role a2apb.Role) a2a.MessageRole {
	switch role {
	case a2apb.Role_ROLE_USER:
		return a2a.MessageRoleUser
	case a2apb.Role_ROLE_AGENT:
		return a2a.MessageRoleAgent
	default:
		return "" // Corresponds to ROLE_UNSPECIFIED
	}
}

func fromProtoTask(pTask *a2apb.Task) (*a2a.Task, error) {
	if pTask == nil {
		return nil, fmt.Errorf("proto task is nil")
	}
	status, err := fromProtoTaskStatus(pTask.Status)
	if err != nil {
		return nil, fmt.Errorf("failed to convert status: %w", err)
	}
	return &a2a.Task{
		ID:        a2a.TaskID(pTask.Id),
		ContextID: pTask.ContextId,
		Status:    status,
	}, nil
}

func fromProtoTaskStatus(pStatus *a2apb.TaskStatus) (a2a.TaskStatus, error) {
	if pStatus == nil {
		return a2a.TaskStatus{}, fmt.Errorf("proto task status is nil")
	}
	msg, err := fromProtoMessage(pStatus.Update)
	if err != nil {
		return a2a.TaskStatus{}, fmt.Errorf("failed to convert message for task status: %w", err)
	}
	return a2a.TaskStatus{
		State:   fromProtoTaskState(pStatus.State),
		Message: msg,
	}, nil
}

func fromProtoTaskState(pState a2apb.TaskState) a2a.TaskState {
	switch pState {
	case a2apb.TaskState_TASK_STATE_AUTH_REQUIRED:
		return a2a.TaskStateAuthRequired
	case a2apb.TaskState_TASK_STATE_CANCELLED:
		return a2a.TaskStateCanceled
	case a2apb.TaskState_TASK_STATE_COMPLETED:
		return a2a.TaskStateCompleted
	case a2apb.TaskState_TASK_STATE_FAILED:
		return a2a.TaskStateFailed
	case a2apb.TaskState_TASK_STATE_INPUT_REQUIRED:
		return a2a.TaskStateInputRequired
	case a2apb.TaskState_TASK_STATE_REJECTED:
		return a2a.TaskStateRejected
	case a2apb.TaskState_TASK_STATE_SUBMITTED:
		return a2a.TaskStateSubmitted
	case a2apb.TaskState_TASK_STATE_WORKING:
		return a2a.TaskStateWorking
	default:
		return a2a.TaskStateUnknown
	}
}

