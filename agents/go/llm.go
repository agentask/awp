// A minimal xAI Grok client: plain net/http against the OpenAI-compatible
// /v1/chat/completions endpoint. No LLM SDK dependency — this repo's
// general minimal-dependency ethos (see root CLAUDE.md: "no cgo anywhere",
// "do NOT pull a [...] library") applies just as well to a single HTTP
// call like this one.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const xaiEndpoint = "https://api.x.ai/v1/chat/completions"

// ChatMessage is one {role, content} turn in a Grok chat completion
// request/response.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// GrokClient calls the xAI chat completions endpoint.
type GrokClient struct {
	APIKey string
	Model  string
	HTTP   *http.Client
}

func NewGrokClient(apiKey, model string) *GrokClient {
	return &GrokClient{
		APIKey: apiKey,
		Model:  model,
		HTTP:   &http.Client{Timeout: 60 * time.Second},
	}
}

type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message ChatMessage `json:"message"`
	} `json:"choices"`
}

// Complete sends systemPrompt plus history (prior turns) plus a final user
// message with userContent, and returns the model's reply text.
func (g *GrokClient) Complete(ctx context.Context, systemPrompt string, history []ChatMessage, userContent string) (string, error) {
	messages := make([]ChatMessage, 0, len(history)+2)
	messages = append(messages, ChatMessage{Role: "system", Content: systemPrompt})
	messages = append(messages, history...)
	messages = append(messages, ChatMessage{Role: "user", Content: userContent})

	reqBody, err := json.Marshal(chatCompletionRequest{
		Model:       g.Model,
		Messages:    messages,
		Temperature: 0.7,
	})
	if err != nil {
		return "", fmt.Errorf("llm: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, xaiEndpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("llm: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm: request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("llm: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm: xAI returned status %d: %s", resp.StatusCode, raw)
	}

	var out chatCompletionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("llm: parse response: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("llm: no choices in response: %s", raw)
	}
	return out.Choices[0].Message.Content, nil
}
