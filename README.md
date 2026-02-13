# Quiver Protocol
A simple quic protocol for nockpool mining. [Nockpool](https://nockpool.com/)

## Stream Model
- Bi stream 1: authentication (`api_key` -> `authenticated|rejected`)
- Bi stream 2: device info (`DeviceInfo` -> `accepted|rejected`)
- Uni stream: server-pushed template updates
- Bi streams (client-opened): submission request/response pairs
- Optional long-lived bi stream: telemetry frames (marker-prefixed)
