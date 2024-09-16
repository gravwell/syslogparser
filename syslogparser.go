// Package syslogparser implements functions to parsing RFC3164 or RFC5424 syslog messages.
// syslogparser provides one subpackage per RFC with an example usage for which RFC.
package syslogparser

import (
	"bytes"
	"errors"
	"time"

	"github.com/gravwell/syslogparser/parsercommon"
)

type RFC uint8

const (
	RFC_UNKNOWN = iota
	RFC_3164
	RFC_5424
)

var (
	errNoHeader = errors.New("no syslog header")
)

type LogParts map[string]interface{}

type LogParser interface {
	Parse() error
	Dump() LogParts
	WithTimestampFormat(string)
	WithLocation(*time.Location)
	WithHostname(string)
	WithTag(string)
}

func DetectRFC(buff []byte) (RFC, error) {
	max := 10
	var v int
	var err error

	if max > len(buff) {
		max = len(buff)
	}

	idx := bytes.IndexByte(buff, '>')
	if idx == -1 || idx >= max {
		//there is no complete header for RFC5424, throw RFC_3164
		return RFC_3164, nil
	}

	idx = idx + 1
	v, err = parsercommon.ParseVersion(buff, &idx, max)
	if err != nil {
		return RFC_UNKNOWN, err
	}

	if v == parsercommon.NO_VERSION {
		return RFC_3164, nil
	}

	return RFC_5424, nil
}
