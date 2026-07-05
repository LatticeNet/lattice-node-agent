package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	agentHTTPErrorMaxBody    = 64 << 10
	agentHTTPErrorMaxSummary = 512
	latticeRequestIDHeader   = "X-Lattice-Request-ID"
)

type agentHTTPStatusError struct {
	statusCode int
	err        error
}

func (e *agentHTTPStatusError) Error() string {
	return e.err.Error()
}

func (e *agentHTTPStatusError) Unwrap() error {
	return e.err
}

func agentHTTPStatusCode(err error) (int, bool) {
	var statusErr *agentHTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.statusCode, true
	}
	return 0, false
}

func agentHTTPError(resp *http.Response, operation string) error {
	body, truncated := readAgentHTTPErrorBody(resp.Body)
	requestID := strings.TrimSpace(resp.Header.Get(latticeRequestIDHeader))

	if apiErr, ok := decodeAgentAPIError(body); ok {
		if strings.TrimSpace(apiErr.RequestID) != "" {
			requestID = strings.TrimSpace(apiErr.RequestID)
		}
		message := strings.TrimSpace(apiErr.Message)
		if message == "" {
			message = http.StatusText(resp.StatusCode)
		}
		return &agentHTTPStatusError{
			statusCode: resp.StatusCode,
			err:        formatAgentHTTPError(operation, resp, apiErr.Code, message, requestID),
		}
	}

	summary := ""
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && isAgentTextErrorBody(resp.Header.Get("Content-Type"), body) {
		summary = truncateAgentHTTPErrorSummary(strings.TrimSpace(string(body)), truncated)
	}
	return &agentHTTPStatusError{
		statusCode: resp.StatusCode,
		err:        formatAgentHTTPError(operation, resp, "", summary, requestID),
	}
}

func readAgentHTTPErrorBody(body io.Reader) ([]byte, bool) {
	if body == nil {
		return nil, false
	}
	data, _ := io.ReadAll(io.LimitReader(body, agentHTTPErrorMaxBody+1))
	if len(data) > agentHTTPErrorMaxBody {
		return data[:agentHTTPErrorMaxBody], true
	}
	return data, false
}

func decodeAgentAPIError(body []byte) (model.APIError, bool) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return model.APIError{}, false
	}
	var envelope model.APIErrorResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return model.APIError{}, false
	}
	if strings.TrimSpace(envelope.Error.Code) == "" {
		return model.APIError{}, false
	}
	return envelope.Error, true
}

func isAgentTextErrorBody(contentType string, body []byte) bool {
	if len(body) == 0 || !utf8.Valid(body) || strings.Contains(string(body), "\x00") {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.TrimSpace(strings.ToLower(contentType))
	}
	if mediaType == "" {
		return true
	}
	return mediaType == "text/plain"
}

func truncateAgentHTTPErrorSummary(summary string, alreadyTruncated bool) string {
	if summary == "" {
		return ""
	}
	runes := []rune(summary)
	if len(runes) > agentHTTPErrorMaxSummary {
		return string(runes[:agentHTTPErrorMaxSummary]) + "...truncated"
	}
	if alreadyTruncated {
		return summary + "...truncated"
	}
	return summary
}

func formatAgentHTTPError(operation string, resp *http.Response, code string, message string, requestID string) error {
	parts := []string{fmt.Sprintf("%s: server returned %s", operation, agentHTTPStatus(resp))}
	if strings.TrimSpace(code) != "" {
		parts = append(parts, strings.TrimSpace(code))
	}
	if strings.TrimSpace(message) != "" {
		parts = append(parts, strings.TrimSpace(message))
	}
	errText := strings.Join(parts, ": ")
	if strings.TrimSpace(requestID) != "" {
		errText += " (request_id=" + strings.TrimSpace(requestID) + ")"
	}
	return fmt.Errorf("%s", errText)
}

func agentHTTPStatus(resp *http.Response) string {
	text := strings.TrimSpace(http.StatusText(resp.StatusCode))
	if text == "" {
		if strings.TrimSpace(resp.Status) != "" {
			return strings.TrimSpace(resp.Status)
		}
		return fmt.Sprintf("%d", resp.StatusCode)
	}
	return fmt.Sprintf("%d %s", resp.StatusCode, text)
}
