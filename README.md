# dnsmonitor

```bash
  -httpHostPort string
      <host>:<port> for exposing the metrics (default "localhost:9111")
  -interface string
      interface to listen on
  -promisc
      promiscuous mode (default true)
  -snaplen int
      packet snap length (default 65536)
  -verbose
      enable debug logging
```

## Build

LDFLAGS='-l/usr/lib/libpcap.a' CGO_ENABLED=1 \
    go build -ldflags '-linkmode external -extldflags -static' -o dnsmon
