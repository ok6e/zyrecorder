# zyrecorder

Simple and minimalistic [ZMQ Zyre](https://github.com/zeromq/zyre) to
[SQLite](https://www.sqlite.org/) recorder tool. This program enters the Zyre network, joins all
peer groups it discovers (and additional explicitly defined groups, if so desired), and records
all SHOUT and WHISPER messages it receives into a table in a SQLite database file.

The message payload ([zmsg](http://czmq.zeromq.org/manual:zmsg)) is encoded as a single
[zframe](http://czmq.zeromq.org/manual:zframe) using `zmsg_encode` and then stored as a blob.
This can be reversed by loading the blob into a `zframe` and using `zmsg_decode` to decode the
original `zmsg` out of the encoded data.

## Formatters and pretty-print

The recorded database table includes a column for pretty-printed variant of the received payload.
This column is populated by a formatter that can be specified depending on which kind of data
serialization your Zyre communications are using. The formatter is used to transform the received
`zmsg` into a single string that is possibly more human-readable than the raw payload. Examples of
this would be multi-frame messages, messages with binary serializations like Protobuf, etc.

You can easily write your own formatter based on the way you are serializing the messages in your
Zyre communications. Take a look at the example formatters `1string` and `nstrings`.

## Dependencies

The following libraries are required to be available to CMake via PkgConfig:

- SQLite3
- [ZeroMQ](https://github.com/zeromq/libzmq)
- [CZMQ](https://github.com/zeromq/czmq)
- [Zyre](https://github.com/zeromq/zyre)
