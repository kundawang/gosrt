/*
Package srt provides an interface for network I/O using the SRT protocol (https://github.com/Haivision/srt).

The package gives access to the basic interface provided by the Dial, Listen, and Accept functions and the associated
Conn and Listener interfaces.

The Dial function connects to a server:

	conn, err := srt.Dial("srt", "golang.org:6000", srt.Config{
		StreamId: "...",
	})
	if err != nil {
		// handle error
	}

	buffer := make([]byte, 2048)

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			// handle error
		}

		// handle received data
	}

	conn.Close()

The Listen function creates servers:

	ln, err := srt.Listen("srt", ":6000", srt.Config{...})
	if err != nil {
		// handle error
	}

	for {
		conn, mode, err := ln.Accept(handleConnect)
		if err != nil {
			// handle error
		}

		if mode == srt.REJECT {
			// rejected connection, ignore
			continue
		}

		if mode == srt.PUBLISH {
			go handlePublish(conn)
		} else {
			go handleSubscribe(conn)
		}
	}

The ln.Accept function expects a function that takes a srt.ConnRequest
and returns a srt.ConnType. The srt.ConnRequest lets you retrieve the
streamid with on which you can decide what mode (srt.ConnType) to return.

Check out the Server type that wraps the Listen and Accept into a
convenient framework for your own SRT server.

# Message mode

If Config.MessageAPI is enabled, messages can be sent and received with
preserved boundaries. A message that does not fit into a single SRT data
packet is split into fragments and reassembled by the peer:

	config := srt.DefaultConfig()
	config.MessageAPI = true

	conn, err := srt.Dial("srt", "127.0.0.1:6000", config)
	if err != nil {
		// handle error
	}

	if _, err := conn.WriteMessage([]byte("one subtitle cue")); err != nil {
		// handle error
	}

	buffer := make([]byte, 2048)

	n, err := conn.ReadMessage(buffer)
	if err != nil {
		// handle error: ErrMessageTooSmall, ErrMessageIncomplete, ...
	}

	// buffer[:n] is exactly one message

The Read and Write methods keep their byte stream behavior independent of
this setting. ReadMessage/WriteMessage must not be mixed with Read/ReadPacket
or Write/WritePacket on the same connection.
*/
package srt
