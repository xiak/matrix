package managedserviceonboarding

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// RedisSession is a bounded native RESP2 probe shared by the adapter and
// production-process acceptance gates. It never logs commands or credentials.
type RedisSession struct {
	connection net.Conn
	reader     *bufio.Reader
}

// RedisError is a native protocol rejection, distinct from a transport failure.
type RedisError string

func (e RedisError) Error() string { return string(e) }

func DialRedis(ctx context.Context, endpoint string) (*RedisSession, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "redis" || parsed.User != nil || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Redis acceptance endpoint is invalid")
	}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", parsed.Host)
	if err != nil {
		return nil, errors.New("Redis acceptance connection failed")
	}
	return &RedisSession{connection: connection, reader: bufio.NewReaderSize(connection, 4096)}, nil
}

func (s *RedisSession) Close() error { return s.connection.Close() }

func (s *RedisSession) Command(arguments ...string) (any, error) {
	if len(arguments) == 0 || len(arguments) > 64 {
		return nil, errors.New("Redis acceptance command is invalid")
	}
	var wire strings.Builder
	fmt.Fprintf(&wire, "*%d\r\n", len(arguments))
	for _, argument := range arguments {
		if len(argument) > 16384 {
			return nil, errors.New("Redis acceptance argument is too large")
		}
		fmt.Fprintf(&wire, "$%d\r\n%s\r\n", len(argument), argument)
	}
	if err := s.connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, errors.New("Redis acceptance deadline failed")
	}
	if _, err := io.WriteString(s.connection, wire.String()); err != nil {
		return nil, errors.New("Redis acceptance write failed")
	}
	budget := 65536
	return s.read(0, &budget)
}

func (s *RedisSession) read(depth int, budget *int) (any, error) {
	if depth > 4 {
		return nil, errors.New("Redis acceptance response is too deep")
	}
	line, err := s.reader.ReadSlice('\n')
	*budget -= len(line)
	if err != nil || *budget < 0 || len(line) < 3 || line[len(line)-2] != '\r' {
		return nil, errors.New("Redis acceptance response is invalid")
	}
	kind, value := line[0], string(line[1:len(line)-2])
	switch kind {
	case '+':
		return value, nil
	case '-':
		return nil, RedisError(value)
	case ':':
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, errors.New("Redis acceptance integer is invalid")
		}
		return n, nil
	case '$', '*':
		n, err := strconv.Atoi(value)
		if err != nil || n < -1 || n > *budget {
			return nil, errors.New("Redis acceptance length is invalid")
		}
		if n == -1 {
			return nil, nil
		}
		if kind == '$' {
			*budget -= n + 2
			if *budget < 0 {
				return nil, errors.New("Redis acceptance bulk response is too large")
			}
			content := make([]byte, n+2)
			if _, err := io.ReadFull(s.reader, content); err != nil || content[n] != '\r' || content[n+1] != '\n' {
				return nil, errors.New("Redis acceptance bulk response is invalid")
			}
			return string(content[:n]), nil
		}
		if n > 128 {
			return nil, errors.New("Redis acceptance array is too large")
		}
		values := make([]any, n)
		for i := range values {
			values[i], err = s.read(depth+1, budget)
			if err != nil {
				return nil, err
			}
		}
		return values, nil
	default:
		return nil, errors.New("Redis acceptance response kind is invalid")
	}
}
