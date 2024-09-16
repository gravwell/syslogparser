package syslogparser

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectRFC_3164(t *testing.T) {
	p, err := DetectRFC(
		[]byte(
			"<34>Oct 11 22:14:15 ...",
		),
	)

	require.Nil(t, err)
	require.Equal(t, p, RFC(RFC_3164))
}

func TestDetectRFC_3164NoHeader(t *testing.T) {
	p, err := DetectRFC(
		[]byte(
			"Oct 11 22:14:15 ...",
		),
	)

	require.Nil(t, err)
	require.Equal(t, p, RFC(RFC_3164))
}

func TestDetectRFC_3164NoHeaderShort(t *testing.T) {
	p, err := DetectRFC(
		[]byte(
			"foo",
		),
	)

	require.Nil(t, err)
	require.Equal(t, p, RFC(RFC_3164))
}

func TestDetectJustHeader(t *testing.T) {
	p, err := DetectRFC(
		[]byte(
			"<34>",
		),
	)

	require.NotNil(t, err)
	require.Equal(t, p, RFC(RFC_UNKNOWN))
}

func TestDetectJustHeaderRFC5424(t *testing.T) {
	p, err := DetectRFC(
		[]byte(
			"<34>1",
		),
	)

	require.Nil(t, err)
	require.Equal(t, p, RFC(RFC_5424))
}

func TestDetectRFC_5424(t *testing.T) {
	p, err := DetectRFC(
		[]byte(
			"<165>1 2003-10-11T22:14:15.003Z ...",
		),
	)

	require.Nil(t, err)
	require.Equal(t, p, RFC(RFC_5424))
}

func BenchmarkDetectRFC(b *testing.B) {
	buff := []byte(
		"<165>1 2003-10-11T22:14:15.003Z ...",
	)

	for i := 0; i < b.N; i++ {
		_, err := DetectRFC(buff)
		if err != nil {
			panic(err)
		}
	}
}
