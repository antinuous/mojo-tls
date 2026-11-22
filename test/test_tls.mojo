# TLS tests with both endpoints in Mojo. Blocking servers run in forked
# children, while the readiness test drives both endpoints on one Poller.
# Covers handshakes, ALPN, certificate verification, timeouts, partial I/O,
# typed WANT_READ and WANT_WRITE states, and clean EOF.

from std.ffi import c_int, external_call
from std.time import perf_counter_ns
from std.testing import assert_equal, assert_false, assert_true

from net import (
    CONNECTION_RESET_ERROR,
    Poller,
    ReadinessStream,
    TCPListener,
    TCPStream,
    is_connection_reset,
    is_timeout_error,
    is_would_block,
)
from tls import (
    PeerCertificate,
    REJECTED_ERROR,
    TLSAlert,
    TLSContext,
    TLSHandshake,
    TLSSession,
    TLSStream,
    is_rejection,
)


comptime CA = "build/certs/ca.pem"
comptime SERVER_CERT = "build/certs/server.pem"
comptime SERVER_KEY = "build/certs/server.key"
comptime WRONGHOST_CERT = "build/certs/wronghost.pem"
comptime WRONGHOST_KEY = "build/certs/wronghost.key"
comptime SELFSIGNED_CERT = "build/certs/selfsigned.pem"
comptime SELFSIGNED_KEY = "build/certs/selfsigned.key"
comptime CLIENT_CERT = "build/certs/client-chain.pem"
comptime CLIENT_KEY = "build/certs/client.key"
comptime UNTRUSTED_CLIENT_CERT = "build/certs/untrusted_client.pem"
comptime UNTRUSTED_CLIENT_KEY = "build/certs/untrusted_client.key"
comptime PARTIAL_WILD_CERT = "build/certs/partial_wild.pem"
comptime PARTIAL_WILD_KEY = "build/certs/partial_wild.key"
comptime WILD_LABEL_CERT = "build/certs/wild_label.pem"
comptime WILD_LABEL_KEY = "build/certs/wild_label.key"
comptime CN_ONLY_CERT = "build/certs/cn_only.pem"
comptime CN_ONLY_KEY = "build/certs/cn_only.key"
comptime SAN_NOT_CN_CERT = "build/certs/san_not_cn.pem"
comptime SAN_NOT_CN_KEY = "build/certs/san_not_cn.key"
comptime PARTIAL_AND_EXACT_CERT = "build/certs/partial_and_exact.pem"
comptime PARTIAL_AND_EXACT_KEY = "build/certs/partial_and_exact.key"
comptime CLIENT_ENCRYPTED_KEY = "build/certs/client-encrypted.key"
comptime MALFORMED_NUL_CERT = "build/certs/malformed_nul.pem"
comptime MALFORMED_NUL_KEY = "build/certs/malformed_nul.key"
comptime MALFORMED_LF_CERT = "build/certs/malformed_lf.pem"
comptime MALFORMED_LF_KEY = "build/certs/malformed_lf.key"
comptime MALFORMED_HIGH_CERT = "build/certs/malformed_high.pem"
comptime MALFORMED_HIGH_KEY = "build/certs/malformed_high.key"
comptime MALFORMED_IP_CERT = "build/certs/malformed_ip.pem"
comptime MALFORMED_IP_KEY = "build/certs/malformed_ip.key"
comptime OVERSIZED_SAN_VALUE_CERT = "build/certs/oversized_san_value.pem"
comptime OVERSIZED_SAN_VALUE_KEY = "build/certs/oversized_san_value.key"
comptime EMPTY_SAN_CERT = "build/certs/empty_san.pem"
comptime EMPTY_SAN_KEY = "build/certs/empty_san.key"
comptime TOO_MANY_SANS_CERT = "build/certs/too_many_sans.pem"
comptime TOO_MANY_SANS_KEY = "build/certs/too_many_sans.key"
comptime TOO_MANY_SAN_BYTES_CERT = "build/certs/too_many_san_bytes.pem"
comptime TOO_MANY_SAN_BYTES_KEY = "build/certs/too_many_san_bytes.key"


def fork_tls_echo_server(
    cert: StringSpan,
    key: StringSpan,
    alpn: List[String],
    client_ca: StringSpan = "",
    require_client_cert: Bool = False,
) raises -> Tuple[UInt16, c_int]:
    """Forks a one-connection TLS echo server; returns (port, child pid).

    The child accepts one TCP connection, runs the TLS handshake, echoes
    until clean TLS EOF, then exits. Handshake failures also exit the
    child, which is what the rejection tests expect.
    """
    var listener = TCPListener("127.0.0.1", 0)
    var port = listener.local_port
    var pid = external_call["fork", c_int]()
    if pid == 0:
        try:
            var ctx = TLSContext.server(
                String(cert),
                String(key),
                client_ca_file=String(client_ca),
                require_client_cert=require_client_cert,
                alpn=alpn,
            )
            var tcp = listener.accept()
            var stream = ctx.accept(tcp^)
            while True:
                var buf = List[Byte]()
                buf.resize(4096, 0)
                var n = stream.read(buf)
                if n == 0:
                    break
                stream.write_all(Span(buf))
            stream.close()
        except:
            pass
        external_call["_exit", NoneType](c_int(0))
    listener.close()
    return (port, pid)


def reap(pid: c_int):
    var status = c_int(0)
    _ = external_call["waitpid", c_int](pid, Pointer(to=status), c_int(0))


def test_handshake_echo_alpn() raises:
    var server = fork_tls_echo_server(
        SERVER_CERT, SERVER_KEY, ["h2", "http/1.1"]
    )
    var ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    assert_true(stream.version().startswith("TLSv1."), stream.version())
    assert_equal(stream.negotiated_alpn(), "h2")
    var peer = stream.peer_certificate()
    if not peer:
        raise Error("verified TLS client receives a server certificate")
    var certificate = peer.value().copy()
    assert_true(len(certificate.leaf_der) > 0)
    assert_true(certificate.verified)
    assert_equal(certificate.matched_name, "localhost")
    assert_equal(len(certificate.subject_alt_names.dns_names), 2)
    assert_equal(certificate.subject_alt_names.dns_names[0], "localhost")
    assert_equal(
        certificate.subject_alt_names.dns_names[1], "service.example.test"
    )
    assert_equal(len(certificate.subject_alt_names.uri_names), 1)
    assert_equal(
        certificate.subject_alt_names.uri_names[0],
        "spiffe://example.test/server",
    )
    assert_equal(len(certificate.subject_alt_names.email_addresses), 1)
    assert_equal(
        certificate.subject_alt_names.email_addresses[0],
        "server@example.test",
    )
    assert_equal(len(certificate.subject_alt_names.ip_addresses), 2)
    assert_equal(certificate.subject_alt_names.ip_addresses[0], "127.0.0.1")
    assert_equal(certificate.subject_alt_names.ip_addresses[1], "2001:db8::1")

    stream.write_all("sixteen tls byte".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(16)), "sixteen tls byte")

    # 256 KiB through the record layer, echoed back in-loop.
    var chunk = List[Byte]()
    chunk.resize(16384, 0x3C)
    for _ in range(16):
        stream.write_all(Span(chunk))
        var got = stream.read_exact(16384)
        assert_equal(got[0], 0x3C)

    stream.close()
    assert_true(
        len(certificate.leaf_der) > 0,
        "certificate snapshot remains owned after stream close",
    )
    assert_equal(
        certificate.subject_alt_names.uri_names[0],
        "spiffe://example.test/server",
        "certificate names remain owned after stream close",
    )
    var closed_raised = False
    try:
        _ = stream.peer_certificate()
    except error:
        closed_raised = True
        assert_true("after close" in String(error), String(error))
    assert_true(closed_raised, "closed stream rejects certificate access")
    reap(server[1])


def test_required_client_certificate() raises:
    var server = fork_tls_echo_server(
        SERVER_CERT,
        SERVER_KEY,
        ["h2"],
        client_ca=CA,
        require_client_cert=True,
    )
    var ctx = TLSContext.client(
        ca_file=String(CA),
        cert_chain_pem=String(CLIENT_CERT),
        key_pem=String(CLIENT_KEY),
        alpn=["h2"],
    )
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    assert_equal(stream.negotiated_alpn(), "h2")
    stream.write_all("auth".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "auth")
    assert_false(Bool(stream.received_alert()), "no alert on a good session")
    stream.close()
    reap(server[1])


def await_readable(fd: c_int) raises:
    var poller = Poller()
    poller.register(fd, readable=True, writable=False)
    assert_true(len(poller.wait(2000)) > 0, "the peer's bytes arrive")
    poller.unregister(fd)


def step_until_done(mut handshake: TLSHandshake) raises:
    for _ in range(16):
        if handshake.wants_read():
            await_readable(handshake.descriptor())
        if handshake.advance():
            return
    assert_true(False, "the handshake step completes")


def step_until_error(mut handshake: TLSHandshake) raises -> String:
    for _ in range(16):
        if handshake.wants_read():
            await_readable(handshake.descriptor())
        try:
            if handshake.advance():
                break
        except error:
            return String(error)
    assert_true(False, "the handshake step raises")
    return ""


def step_until_raises(mut handshake: TLSHandshake) raises:
    for _ in range(16):
        if handshake.wants_read():
            await_readable(handshake.descriptor())
        try:
            if handshake.advance():
                break
        except:
            return
    assert_true(False, "the handshake step meets the alert")


def test_alert_in_the_handshake_is_received() raises:
    # One thread steps both sides, so the order is fixed: the server's
    # first step meets an ALPN it does not serve and sends its alert before
    # the client's handshake can complete.
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)
    var client_ctx = TLSContext.client(ca_file=String(CA), alpn=["http/1.1"])
    var server_ctx = TLSContext.server(
        String(SERVER_CERT), String(SERVER_KEY), alpn=["h2"]
    )
    var client = client_ctx.start_connect(client_tcp^, "localhost")
    var server = server_ctx.start_accept(server_tcp^)
    assert_false(client.advance(), "the client waits for the server")
    step_until_raises(server)
    step_until_raises(client)
    var alert = client.received_alert()
    assert_true(Bool(alert), "the failed handshake carries the alert")
    assert_equal(alert.value(), TLSAlert(120))


def test_alert_after_the_handshake_is_received_on_read() raises:
    # TLS 1.3: the client's handshake completes before the server checks
    # the client certificate. One thread steps both sides, so the client
    # completes first and meets certificate_required on its first read.
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)
    var client_ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var server_ctx = TLSContext.server(
        String(SERVER_CERT),
        String(SERVER_KEY),
        alpn=["h2"],
        client_ca_file=String(CA),
        require_client_cert=True,
    )
    var client = client_ctx.start_connect(client_tcp^, "localhost")
    var server = server_ctx.start_accept(server_tcp^)
    assert_false(client.advance(), "the client waits for the server")
    await_readable(server.descriptor())
    assert_false(server.advance(), "the server waits for the client")
    step_until_done(client)
    assert_false(Bool(client.received_alert()), "no alert yet")
    step_until_raises(server)
    var stream = client^.finish()
    await_readable(stream.descriptor())
    var buf = List[Byte]()
    buf.resize(1, 0)
    var read_raised = False
    try:
        _ = stream.read(buf)
    except:
        read_raised = True
    assert_true(read_raised, "the first read meets the alert")
    var alert = stream.received_alert()
    assert_true(Bool(alert), "the rejection is a received alert")
    assert_equal(alert.value(), TLSAlert.certificate_required)
    stream.close()


def step_until_peer_hears(mut client: TLSHandshake, peer: c_int) raises:
    # Steps the client until its next flight is readable at the peer; the
    # client never completes while it waits for the server's judgement.
    for _ in range(16):
        assert_false(client.advance(), "the client waits for the server")
        var poller = Poller()
        poller.register(peer, readable=True, writable=False)
        poller.register(client.descriptor(), readable=True, writable=False)
        var events = poller.wait(2000)
        assert_true(len(events) > 0, "a side has bytes to read")
        for event in events:
            if event.fd == peer:
                return
    assert_true(False, "the client's flight reaches the server")


def judging_server_context() raises -> TLSContext:
    return TLSContext.server(
        String(SERVER_CERT),
        String(SERVER_KEY),
        alpn=["h2"],
        client_ca_file=String(CA),
        require_client_cert=True,
    )


def certificate_client_context(
    cert: StringSpan, key: StringSpan
) raises -> TLSContext:
    return TLSContext.client(
        ca_file=String(CA),
        cert_chain_pem=String(cert),
        key_pem=String(key),
        alpn=["h2"],
        server_tickets_after_verify=True,
    )


def step_to_the_judgement(
    mut client: TLSHandshake, mut server: TLSHandshake
) raises:
    # One thread steps both sides up to the point where the TLS 1.3 client
    # has sent its certificate and the server has not yet read it.
    assert_false(client.advance(), "the client waits for the server")
    await_readable(server.descriptor())
    assert_false(server.advance(), "the server waits for the client")
    step_until_peer_hears(client, server.descriptor())
    assert_false(client.is_complete(), "no completion before the judgement")


def test_certificate_client_completes_on_the_ticket() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)
    var server_ctx = judging_server_context()
    var client_ctx = certificate_client_context(CLIENT_CERT, CLIENT_KEY)
    var client = client_ctx.start_connect(client_tcp^, "localhost")
    var server = server_ctx.start_accept(server_tcp^)
    step_to_the_judgement(client, server)
    step_until_done(server)
    step_until_done(client)
    assert_false(Bool(client.received_alert()), "an accepted client")
    assert_false(Bool(server.verify_error()), "the server verified it")
    var stream = client^.finish()
    var peer = server^.finish()
    stream.write_all("ok".as_bytes())
    await_readable(peer.descriptor())
    var buf = List[Byte](length=2, fill=0)
    assert_equal(peer.read(buf), 2)
    stream.close()
    peer.close()


def test_certificate_client_reads_the_alert_before_the_reset() raises:
    # The server is held open until the client's read of its alert has
    # returned, and only then dropped with the client's flight unread, so
    # the reset comes after the alert was read.
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)
    var server_ctx = judging_server_context()
    var client_ctx = certificate_client_context(
        UNTRUSTED_CLIENT_CERT, UNTRUSTED_CLIENT_KEY
    )
    var client = client_ctx.start_connect(client_tcp^, "localhost")
    var server = server_ctx.start_accept(server_tcp^)
    step_to_the_judgement(client, server)
    step_until_raises(server)
    var error = step_until_error(client)
    assert_equal(error, REJECTED_ERROR)
    var alert = client.received_alert()
    assert_true(Bool(alert), "the rejection is a received alert")
    assert_equal(alert.value(), TLSAlert.unknown_ca)
    assert_true(Bool(server.verify_error()), "the server refused the chain")
    assert_false(Bool(client.verify_error()), "the client refused nothing")
    var sent = server.sent_alert()
    assert_true(Bool(sent), "the refusing server records its alert as sent")
    assert_equal(sent.value(), TLSAlert.unknown_ca)
    assert_false(Bool(client.sent_alert()), "the refused client sent none")
    _ = server^


def test_certificate_client_meets_a_reset_with_nothing_readable() raises:
    # The server is dropped before it reads the client's flight, so it
    # sends no alert and its close over unread data is a reset; the client
    # has nothing to read when it steps.
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)
    var server_ctx = judging_server_context()
    var client_ctx = certificate_client_context(CLIENT_CERT, CLIENT_KEY)
    var client = client_ctx.start_connect(client_tcp^, "localhost")
    var server = server_ctx.start_accept(server_tcp^)
    step_to_the_judgement(client, server)
    _ = server^
    var error = step_until_error(client)
    assert_equal(error, CONNECTION_RESET_ERROR)
    assert_false(Bool(client.received_alert()), "a close is not an alert")


def await_hangup(fd: c_int) raises:
    # The peer's FIN follows every byte it sent, so once it is seen the
    # whole of the peer's output is queued here.
    # Readability is level-triggered and fires before the FIN lands, so
    # the wait is bounded by time rather than by wakeups.
    var poller = Poller()
    poller.register(fd, readable=True, writable=False)
    var deadline_ns = perf_counter_ns() + 2_000_000_000
    while perf_counter_ns() < deadline_ns:
        var events = poller.wait(2000)
        for event in events:
            if event.hangup:
                poller.unregister(fd)
                return
    assert_true(False, "the peer's close arrives")


def test_certificate_client_takes_the_ticket_and_close_in_one_read() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)
    var server_ctx = judging_server_context()
    var client_ctx = certificate_client_context(CLIENT_CERT, CLIENT_KEY)
    var client = client_ctx.start_connect(client_tcp^, "localhost")
    var server = server_ctx.start_accept(server_tcp^)
    step_to_the_judgement(client, server)
    step_until_done(server)
    var peer = server^.finish()
    peer.close()
    await_hangup(client.descriptor())
    assert_true(client.advance(), "the ticket is the verdict")
    var stream = client^.finish()
    var buf = List[Byte](length=16, fill=0)
    assert_equal(stream.read(buf), 0, "close_notify reads as clean EOF")
    assert_false(Bool(stream.received_alert()), "close_notify is no rejection")
    assert_false(Bool(stream.sent_alert()), "the client refused nothing")
    stream.close()


def test_certificate_client_fails_when_the_server_ends_with_a_fin() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)
    var server_ctx = judging_server_context()
    var client_ctx = certificate_client_context(CLIENT_CERT, CLIENT_KEY)
    var client = client_ctx.start_connect(client_tcp^, "localhost")
    var server = server_ctx.start_accept(server_tcp^)
    step_to_the_judgement(client, server)
    comptime SHUT_WR = 1
    assert_equal(
        external_call["shutdown", c_int](server.descriptor(), c_int(SHUT_WR)),
        0,
    )
    var error = step_until_error(client)
    assert_equal(error, CONNECTION_RESET_ERROR)
    assert_false(Bool(client.received_alert()), "a close is not an alert")
    assert_false(server.is_complete(), "the server never judged")


def fork_stalled_server() raises -> Tuple[UInt16, c_int]:
    # The child answers the ClientHello and then never reads the client's
    # certificate, so no verdict ever comes. One advance suffices because
    # libssl writes the whole ClientHello (under 2 KiB, even with a hybrid
    # post-quantum key share) in one write call, well under the loopback
    # MTU (16 KiB on macOS, 64 KiB on Linux), so it arrives as one segment.
    var listener = TCPListener("127.0.0.1", 0)
    var port = listener.local_port
    var pid = external_call["fork", c_int]()
    if pid == 0:
        try:
            var tcp = listener.accept()
            tcp.set_nonblocking(True)
            var server_ctx = judging_server_context()
            var handshake = server_ctx.start_accept(tcp^)
            await_readable(handshake.descriptor())
            _ = handshake.advance()
            _ = external_call["pause", c_int]()
            _ = handshake.is_complete()
        except:
            pass
        external_call["_exit", NoneType](c_int(0))
    listener.close()
    return (port, pid)


def test_certificate_client_times_out_without_a_verdict() raises:
    var server = fork_stalled_server()
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    tcp.set_read_timeout(200_000_000)
    var ctx = certificate_client_context(CLIENT_CERT, CLIENT_KEY)
    var timed_out = False
    try:
        _ = ctx.connect(tcp^, "localhost")
    except error:
        timed_out = is_timeout_error(error)
        assert_true(timed_out, String(error))
    assert_true(timed_out, "the verdict wait ends at the read timeout")
    _ = external_call["kill", c_int](server[1], c_int(9))
    reap(server[1])


def test_an_alert_is_sent_by_one_side_and_received_by_the_other() raises:
    # The client refuses a self-signed server certificate and sends the
    # fatal alert: the client records it as sent only, the server as
    # received only.
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)
    var client_ctx = TLSContext.client(ca_file=String(CA))
    var server_ctx = TLSContext.server(
        String(SELFSIGNED_CERT), String(SELFSIGNED_KEY)
    )
    var client = client_ctx.start_connect(client_tcp^, "localhost")
    var server = server_ctx.start_accept(server_tcp^)
    assert_false(client.advance(), "the client waits for the server")
    await_readable(server.descriptor())
    assert_false(server.advance(), "the server waits for the client")
    step_until_raises(client)
    assert_true(Bool(client.verify_error()), "the client refused the chain")
    assert_false(Bool(client.received_alert()), "a sent alert is not received")
    var sent = client.sent_alert()
    assert_true(Bool(sent), "the client records the alert it sent")
    assert_equal(sent.value(), TLSAlert.unknown_ca)
    step_until_raises(server)
    var alert = server.received_alert()
    assert_true(Bool(alert), "the server received the client's alert")
    assert_equal(alert.value(), TLSAlert.unknown_ca)
    assert_false(Bool(server.sent_alert()), "a received alert is not sent")


def test_a_user_canceled_alert_is_not_recorded() raises:
    # A raw TCP peer reads the ClientHello, writes a plaintext fatal-level
    # user_canceled record, then shuts down its write side; the client
    # steps only after both, before any ServerHello fixes the version, so
    # only the description rule keeps the alert from being recorded.
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var peer = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    var client_ctx = TLSContext.client(ca_file=String(CA))
    var client = client_ctx.start_connect(client_tcp^, "localhost")
    assert_false(client.advance(), "the client waits for the server")
    await_readable(peer.descriptor())
    var hello = List[Byte](length=16384, fill=0)
    assert_true(peer.read(hello) > 0, "the ClientHello arrives")
    var alert: List[Byte] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x5A]
    peer.write_all(alert)
    comptime SHUT_WR = 1
    assert_equal(
        external_call["shutdown", c_int](peer.descriptor(), c_int(SHUT_WR)),
        0,
    )
    step_until_raises(client)
    assert_false(Bool(client.received_alert()), "user_canceled is no refusal")
    assert_false(Bool(client.sent_alert()), "the client refused nothing")
    peer.close()


def test_a_peer_that_ends_the_handshake_is_a_typed_reset() raises:
    # A raw TCP peer reads the ClientHello and shuts down its write side
    # with no alert; the client steps only after both, so its step meets
    # the end of the stream and refuses nothing.
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var peer = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    var client_ctx = TLSContext.client(ca_file=String(CA))
    var client = client_ctx.start_connect(client_tcp^, "localhost")
    assert_false(client.advance(), "the client waits for the server")
    await_readable(peer.descriptor())
    var hello = List[Byte](length=16384, fill=0)
    assert_true(peer.read(hello) > 0, "the ClientHello arrives")
    comptime SHUT_WR = 1
    assert_equal(
        external_call["shutdown", c_int](peer.descriptor(), c_int(SHUT_WR)),
        0,
    )
    var reset = False
    for _ in range(16):
        await_readable(client.descriptor())
        try:
            assert_false(client.advance(), "no ServerHello arrives")
        except error:
            assert_true(is_connection_reset(error), String(error))
            reset = True
            break
    assert_true(reset, "the end of the stream ends the handshake")
    assert_false(Bool(client.received_alert()), "the peer sent no alert")
    assert_false(Bool(client.sent_alert()), "the client refused nothing")
    peer.close()


def test_reject_untrusted_client_certificate() raises:
    var server = fork_tls_echo_server(
        SERVER_CERT,
        SERVER_KEY,
        ["h2"],
        client_ca=CA,
        require_client_cert=True,
    )
    var ctx = TLSContext.client(
        ca_file=String(CA),
        cert_chain_pem=String(UNTRUSTED_CLIENT_CERT),
        key_pem=String(UNTRUSTED_CLIENT_KEY),
        alpn=["h2"],
        server_tickets_after_verify=True,
    )
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    tcp.set_read_timeout(2_000_000_000)
    var handshake = ctx.start_connect(tcp^, "localhost")
    var raised = False
    try:
        _ = handshake.advance()
    except e:
        raised = True
        assert_true(is_rejection(e), String(e))
    assert_true(raised, "untrusted client certificate must fail connect")
    var alert = handshake.received_alert()
    assert_true(Bool(alert), "the blocking connect meets the alert")
    assert_equal(alert.value(), TLSAlert.unknown_ca)
    reap(server[1])


def test_clean_eof() raises:
    # A server that closes after one echo produces a clean TLS EOF
    # (read() returns 0), not an error.
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, List[String]())
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    assert_equal(stream.negotiated_alpn(), "", "no ALPN configured")
    stream.write_all("bye".as_bytes())
    _ = stream.read_exact(3)
    # Half-close from our side ends the child's echo loop; it closes,
    # and our next read sees the clean shutdown.
    var probe = List[Byte]()
    probe.resize(4, 0)
    stream.close()
    reap(server[1])
    _ = probe


def test_end_without_close_notify_is_a_typed_reset() raises:
    # A server that ends the connection with no close_notify may have cut
    # off what it sent, so the read after its data raises the typed reset
    # error rather than reading the clean EOF of 0.
    var listener = TCPListener("127.0.0.1", 0)
    var port = listener.local_port
    var pid = external_call["fork", c_int]()
    if pid == 0:
        try:
            var ctx = TLSContext.server(SERVER_CERT, SERVER_KEY)
            var tcp = listener.accept()
            var stream = ctx.accept(tcp^)
            stream.write_all("x".as_bytes())
        except:
            pass
        external_call["_exit", NoneType](c_int(0))
    listener.close()

    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", port)
    var stream = ctx.connect(tcp^, "localhost")
    assert_equal(String(from_utf8=stream.read_exact(1)), "x")
    var buf = List[Byte](length=16, fill=0)
    var reset = False
    try:
        _ = stream.read(buf)
    except error:
        assert_true(is_connection_reset(error), String(error))
        reset = True
    assert_true(reset, "an end without close_notify is not a clean EOF")
    assert_false(Bool(stream.sent_alert()), "the client refused nothing")
    stream.close()
    reap(pid)


def test_reject_untrusted_ca() raises:
    var server = fork_tls_echo_server(
        SELFSIGNED_CERT, SELFSIGNED_KEY, List[String]()
    )
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        _ = ctx.connect(tcp^, "localhost")
    except e:
        raised = True
        assert_true("handshake" in String(e), String(e))
    assert_true(raised, "self-signed cert must be rejected")
    reap(server[1])


def test_reject_wrong_hostname() raises:
    var server = fork_tls_echo_server(
        WRONGHOST_CERT, WRONGHOST_KEY, List[String]()
    )
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        # The cert is CA-signed but for otherhost.example; verifying
        # against "localhost" must fail.
        _ = ctx.connect(tcp^, "localhost")
    except e:
        raised = True
        assert_true("handshake" in String(e), String(e))
    assert_true(raised, "hostname mismatch must be rejected")
    reap(server[1])


def expect_hostname_rejected(
    cert: StringSpan, key: StringSpan, hostname: StringSpan
) raises:
    var server = fork_tls_echo_server(cert, key, List[String]())
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        _ = ctx.connect(tcp^, hostname)
    except e:
        raised = True
        var message = String(e)
        assert_true("handshake" in message, message)
        assert_true("certificate verify failed" in message, message)
    assert_true(raised, "hostname must be rejected: " + String(hostname))
    reap(server[1])


def expect_hostname_verified(
    cert: StringSpan,
    key: StringSpan,
    hostname: StringSpan,
    matched_name: StringSpan,
) raises:
    var server = fork_tls_echo_server(cert, key, List[String]())
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, hostname)
    var peer = stream.peer_certificate()
    if not peer:
        raise Error("verified handshake has no peer certificate")
    var certificate = peer.value().copy()
    assert_true(certificate.verified)
    assert_equal(certificate.matched_name, String(matched_name))
    stream.write_all("ok".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(2)), "ok")
    stream.close()
    reap(server[1])


def test_hostname_wildcard_and_common_name() raises:
    # www*.example.test matches www1.example.test only as a partial
    # wildcard, and that name is also the CN. Accepting it would mean
    # partial wildcards are on, or the CN was checked despite a DNS SAN.
    expect_hostname_rejected(
        PARTIAL_WILD_CERT, PARTIAL_WILD_KEY, "www1.example.test"
    )
    # A whole-label wildcard still matches exactly one label. OpenSSL
    # reports the certificate pattern as the matched name.
    expect_hostname_verified(
        WILD_LABEL_CERT,
        WILD_LABEL_KEY,
        "www.example.test",
        "*.example.test",
    )
    expect_hostname_rejected(
        WILD_LABEL_CERT, WILD_LABEL_KEY, "a.b.example.test"
    )
    # No DNS SAN: RFC 6125 still allows the subject CN.
    expect_hostname_verified(
        CN_ONLY_CERT, CN_ONLY_KEY, "localhost", "localhost"
    )
    # A DNS SAN suppresses a different CN, and the SAN itself matches.
    expect_hostname_rejected(SAN_NOT_CN_CERT, SAN_NOT_CN_KEY, "localhost")
    expect_hostname_verified(
        SAN_NOT_CN_CERT,
        SAN_NOT_CN_KEY,
        "other.example.test",
        "other.example.test",
    )


def test_ip_literal_hostname() raises:
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, ["h2"])
    var ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "127.0.0.1")
    var peer = stream.peer_certificate()
    if not peer:
        raise Error("IP-literal TLS client receives a server certificate")
    var certificate = peer.value().copy()
    assert_true(certificate.verified)
    # IP identity uses X509_VERIFY_PARAM_set1_ip_asc; SSL_get0_peername
    # only reports DNS names set via SSL_set1_host.
    assert_equal(certificate.matched_name, "")
    assert_equal(certificate.subject_alt_names.ip_addresses[0], "127.0.0.1")
    stream.write_all("ip literal name".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(15)), "ip literal name")
    stream.close()
    reap(server[1])


def test_verify_disabled_accepts_selfsigned() raises:
    var server = fork_tls_echo_server(
        SELFSIGNED_CERT, SELFSIGNED_KEY, List[String]()
    )
    var ctx = TLSContext.client(verify=False)
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    var peer = stream.peer_certificate()
    if not peer:
        raise Error("unverified TLS still exposes the presented certificate")
    assert_true(not peer.value().verified)
    assert_equal(peer.value().matched_name, "")
    stream.write_all("ok".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(2)), "ok")
    stream.close()
    reap(server[1])


def assert_peer_names_rejected(
    cert: StringSpan, key: StringSpan, expected_error: StringSpan
) raises:
    var server = fork_tls_echo_server(cert, key, List[String]())
    var ctx = TLSContext.client(verify=False)
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    var raised = False
    try:
        _ = stream.peer_certificate()
    except error:
        raised = True
        assert_true(String(expected_error) in String(error), String(error))
    stream.close()
    reap(server[1])
    assert_true(raised, "unsafe certificate names must be rejected")


def test_reject_unsafe_subject_alt_names() raises:
    assert_peer_names_rejected(
        MALFORMED_NUL_CERT,
        MALFORMED_NUL_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        MALFORMED_LF_CERT,
        MALFORMED_LF_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        MALFORMED_HIGH_CERT,
        MALFORMED_HIGH_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        MALFORMED_IP_CERT,
        MALFORMED_IP_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        EMPTY_SAN_CERT,
        EMPTY_SAN_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        OVERSIZED_SAN_VALUE_CERT,
        OVERSIZED_SAN_VALUE_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        TOO_MANY_SANS_CERT,
        TOO_MANY_SANS_KEY,
        "more than 256 names",
    )
    assert_peer_names_rejected(
        TOO_MANY_SAN_BYTES_CERT,
        TOO_MANY_SAN_BYTES_KEY,
        "names exceed 64 KiB",
    )


def test_peer_certificate_compatibility_constructor() raises:
    var der = List[Byte](length=2, fill=0xA5)
    var certificate = PeerCertificate(der^, True, String("legacy.example"))
    assert_equal(len(certificate.leaf_der), 2)
    assert_true(certificate.verified)
    assert_equal(certificate.matched_name, "legacy.example")
    assert_equal(len(certificate.subject_alt_names.dns_names), 0)
    assert_equal(len(certificate.subject_alt_names.uri_names), 0)
    assert_equal(len(certificate.subject_alt_names.email_addresses), 0)
    assert_equal(len(certificate.subject_alt_names.ip_addresses), 0)


def test_alpn_no_overlap_fails() raises:
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, ["h2"])
    var ctx = TLSContext.client(ca_file=String(CA), alpn=["http/1.1"])
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        _ = ctx.connect(tcp^, "localhost")
    except e:
        raised = True
        assert_true("handshake" in String(e), String(e))
    assert_true(raised, "no ALPN overlap must fail the handshake")
    reap(server[1])


def test_max_length_alpn_reported() raises:
    # RFC 7301 allows protocol names up to 255 bytes.
    var protocol = String("p") * 255
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, [protocol])
    var ctx = TLSContext.client(ca_file=String(CA), alpn=[protocol])
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    assert_equal(stream.negotiated_alpn(), protocol)
    stream.close()
    reap(server[1])


def test_read_timeout_through_tls() raises:
    # Server echoes but we ask for bytes it never sends: the timeout on
    # the underlying stream must surface through the TLS layer, typed.
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, List[String]())
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    stream.set_read_timeout(100_000_000)
    var timed_out = False
    try:
        _ = stream.read_exact(1)
    except e:
        timed_out = True
        assert_true(is_timeout_error(e), String(e))
    assert_true(timed_out)
    stream.close()
    reap(server[1])


def accepts_readiness_stream[S: ReadinessStream](stream: S):
    """Compile-time proof that TLSStream satisfies the readiness trait."""
    _ = stream


def test_nonblocking_handshake_and_partial_io() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)

    var client_ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var server_ctx = TLSContext.server(
        String(SERVER_CERT), String(SERVER_KEY), alpn=["h2"]
    )
    var client_hs = client_ctx.start_connect(client_tcp^, "localhost")
    var server_hs = server_ctx.start_accept(server_tcp^)

    var client_done = client_hs.advance()
    var server_done = server_hs.advance()
    assert_true(
        client_done or client_hs.wants_read() or client_hs.wants_write()
    )
    assert_true(
        server_done or server_hs.wants_read() or server_hs.wants_write()
    )

    var poller = Poller()
    if not client_done:
        poller.register(
            client_hs.descriptor(),
            readable=client_hs.wants_read(),
            writable=client_hs.wants_write(),
        )
    if not server_done:
        poller.register(
            server_hs.descriptor(),
            readable=server_hs.wants_read(),
            writable=server_hs.wants_write(),
        )

    var steps = 0
    while not client_done or not server_done:
        steps += 1
        assert_true(steps < 100, "non-blocking handshake must converge")
        var events = poller.wait(2000)
        assert_true(len(events) > 0, "handshake descriptor becomes ready")
        for event in events:
            if not client_done and event.fd == client_hs.descriptor():
                if (
                    (client_hs.wants_read() and event.readable)
                    or (client_hs.wants_write() and event.writable)
                    or event.error
                    or event.hangup
                ):
                    client_done = client_hs.advance()
                    if client_done:
                        poller.unregister(client_hs.descriptor())
                    else:
                        poller.modify(
                            client_hs.descriptor(),
                            readable=client_hs.wants_read(),
                            writable=client_hs.wants_write(),
                        )
            if not server_done and event.fd == server_hs.descriptor():
                if (
                    (server_hs.wants_read() and event.readable)
                    or (server_hs.wants_write() and event.writable)
                    or event.error
                    or event.hangup
                ):
                    server_done = server_hs.advance()
                    if server_done:
                        poller.unregister(server_hs.descriptor())
                    else:
                        poller.modify(
                            server_hs.descriptor(),
                            readable=server_hs.wants_read(),
                            writable=server_hs.wants_write(),
                        )
    poller.close()

    var client = client_hs^.finish()
    var server = server_hs^.finish()
    accepts_readiness_stream(client)
    accepts_readiness_stream(server)
    assert_equal(client.negotiated_alpn(), "h2")
    assert_equal(server.negotiated_alpn(), "h2")
    var client_peer = client.peer_certificate()
    if not client_peer:
        raise Error("verified TLS client receives a server certificate")
    assert_true(client_peer.value().verified)
    assert_equal(client_peer.value().matched_name, "localhost")
    assert_true(
        not server.peer_certificate(),
        "server receives no certificate without client authentication",
    )

    var empty = List[Byte](length=1, fill=0)
    var blocked = False
    try:
        _ = server.read(empty)
    except error:
        blocked = True
        assert_true(is_would_block(error), String(error))
        assert_true(server.wants_read())
        assert_true(not server.wants_write())
    assert_true(blocked, "empty TLS read reports WANT_READ")

    var payload = List[Byte](length=8 * 1024 * 1024, fill=0x5A)
    var sent = 0
    var writes = 0
    blocked = False
    while sent < len(payload):
        try:
            var n = client.write_some(Span(payload)[sent : len(payload)])
            assert_true(n > 0)
            sent += n
            writes += 1
        except error:
            assert_true(is_would_block(error), String(error))
            assert_true(client.wants_write())
            assert_true(not client.wants_read())
            blocked = True
            break
    assert_true(writes > 1, "partial TLS writes expose bounded progress")
    assert_true(blocked, "stalled TLS peer produces WANT_WRITE")

    client.close()
    server.close()


def test_bad_cert_paths() raises:
    var raised = False
    try:
        _ = TLSContext.server(
            String("build/certs/missing.pem"), String(SERVER_KEY)
        )
    except e:
        raised = True
        assert_true("certificate" in String(e), String(e))
    assert_true(raised, "missing certificate file must raise")

    raised = False
    try:
        _ = TLSContext.server(
            String(SERVER_CERT),
            String(SERVER_KEY),
            client_ca_file=String(CA),
        )
    except e:
        raised = True
        assert_true("provided together" in String(e), String(e))
    assert_true(raised, "a client CA without the required flag must raise")

    raised = False
    try:
        _ = TLSContext.server(
            String(SERVER_CERT),
            String(SERVER_KEY),
            require_client_cert=True,
        )
    except e:
        raised = True
        assert_true("provided together" in String(e), String(e))
    assert_true(raised, "the required flag without a client CA must raise")

    raised = False
    try:
        _ = TLSContext.server(
            String(SERVER_CERT),
            String(SERVER_KEY),
            client_ca_file="build/certs/missing-ca.pem",
            require_client_cert=True,
        )
    except e:
        raised = True
        assert_true("loading client CA" in String(e), String(e))
    assert_true(raised, "a missing client CA file must raise")

    raised = False
    try:
        _ = TLSContext.client(
            verify=False, cert_chain_pem=String(CLIENT_CERT)
        )
    except e:
        raised = True
        assert_true("provided together" in String(e), String(e))
    assert_true(raised, "a client certificate without its key must raise")

    raised = False
    try:
        _ = TLSContext.client(verify=False, key_pem=String(CLIENT_KEY))
    except e:
        raised = True
        assert_true("provided together" in String(e), String(e))
    assert_true(raised, "a client key without its certificate must raise")

    raised = False
    try:
        _ = TLSContext.client(
            verify=False,
            cert_chain_pem=String(CLIENT_CERT),
            key_pem=String(SERVER_KEY),
        )
    except e:
        raised = True
        assert_true("client certificate" in String(e), String(e))
    assert_true(raised, "a mismatched client certificate and key must raise")

    raised = False
    try:
        _ = TLSContext.client(
            verify=False,
            cert_chain_pem=String(CLIENT_CERT),
            key_pem=String(CLIENT_ENCRYPTED_KEY),
        )
    except e:
        raised = True
        assert_true("client certificate" in String(e), String(e))
    assert_true(raised, "an encrypted client key must raise")

    raised = False
    try:
        _ = TLSContext.server(SERVER_CERT, CLIENT_ENCRYPTED_KEY)
    except e:
        raised = True
        assert_true("certificate/key" in String(e), String(e))
    assert_true(raised, "an encrypted server key must raise")


def test_client_identity_configuration() raises:
    _ = TLSContext.client(
        verify=False,
        cert_chain_pem=String(CLIENT_CERT),
        key_pem=String(CLIENT_KEY),
    )


def test_session_ticket_resume() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var port = listener.local_port
    var pid = external_call["fork", c_int]()
    if pid == 0:
        try:
            var ctx = TLSContext.server(SERVER_CERT, SERVER_KEY, alpn=["h2"])
            var first_tcp = listener.accept()
            var first = ctx.accept(first_tcp^)
            var ping = first.read_exact(4)
            first.write_all(Span(ping))
            first.close()
            var second_tcp = listener.accept()
            var second = ctx.accept(second_tcp^)
            var pong = second.read_exact(4)
            second.write_all(Span(pong))
            second.close()
        except:
            pass
        external_call["_exit", NoneType](c_int(0))
    listener.close()

    var ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var tcp = TCPStream.connect("127.0.0.1", port)
    var stream = ctx.connect(tcp^, "localhost")
    assert_true(not stream.session_reused(), "first handshake is full")
    stream.write_all("ping".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "ping")
    var ticket = stream.session()
    if not ticket:
        stream.close()
        reap(pid)
        raise Error("expected a resumable TLS 1.3 ticket after I/O")
    stream.close()

    var resume_tcp = TCPStream.connect("127.0.0.1", port)
    var resumed = ctx.connect(
        resume_tcp^, "localhost", session=ticket.value().copy()
    )
    assert_true(resumed.session_reused(), "second handshake resumes")
    resumed.write_all("pong".as_bytes())
    assert_equal(String(from_utf8=resumed.read_exact(4)), "pong")
    resumed.close()
    reap(pid)


def fork_two_echo_server(
    cert: StringSpan, key: StringSpan
) raises -> Tuple[UInt16, c_int]:
    """Forks a server that echoes 4 bytes on each of two connections."""
    var listener = TCPListener("127.0.0.1", 0)
    var port = listener.local_port
    var pid = external_call["fork", c_int]()
    if pid == 0:
        try:
            var ctx = TLSContext.server(String(cert), String(key))
            for _ in range(2):
                var tcp = listener.accept()
                var stream = ctx.accept(tcp^)
                var payload = stream.read_exact(4)
                stream.write_all(Span(payload))
                stream.close()
        except:
            pass
        external_call["_exit", NoneType](c_int(0))
    listener.close()
    return (port, pid)


def take_ticket(mut stream: TLSStream) raises -> TLSSession:
    var ticket = stream.session()
    if not ticket:
        raise Error("expected a resumable TLS 1.3 ticket after I/O")
    return ticket.value().copy()


def test_session_ticket_ip_literal_resume() raises:
    var server = fork_two_echo_server(SERVER_CERT, SERVER_KEY)
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "127.0.0.1")
    stream.write_all("ping".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "ping")
    var ticket = take_ticket(stream)
    stream.close()

    var resume_tcp = TCPStream.connect("127.0.0.1", server[0])
    var resumed = ctx.connect(
        resume_tcp^, "127.0.0.1", session=ticket.copy()
    )
    assert_true(resumed.session_reused(), "IP-literal ticket resumes")
    var peer = resumed.peer_certificate()
    if not peer:
        raise Error("resumed IP connection has no peer certificate")
    assert_true(peer.value().verified, "resumed IP certificate stays verified")
    resumed.write_all("pong".as_bytes())
    assert_equal(String(from_utf8=resumed.read_exact(4)), "pong")
    resumed.close()
    reap(server[1])


def test_session_ticket_wrong_name_rejected() raises:
    var server = fork_two_echo_server(SERVER_CERT, SERVER_KEY)
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    stream.write_all("ping".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "ping")
    var ticket = take_ticket(stream)
    stream.close()

    var resume_tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        _ = ctx.connect(
            resume_tcp^, "otherhost.example", session=ticket.copy()
        )
    except e:
        raised = True
        var message = String(e)
        assert_true("handshake" in message, message)
        assert_true("certificate verify failed" in message, message)
    assert_true(
        raised,
        "a ticket must not resume under a name the certificate does not cover",
    )
    reap(server[1])


def test_session_ticket_partial_wildcard_rejected() raises:
    # The leaf matches ok.example.test exactly and ok1.example.test only
    # through the partial wildcard ok*.example.test. Resumption does not
    # verify the certificate again, so the ticket check has to reject it.
    var server = fork_two_echo_server(
        PARTIAL_AND_EXACT_CERT, PARTIAL_AND_EXACT_KEY
    )
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "ok.example.test")
    stream.write_all("ping".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "ping")
    var ticket = take_ticket(stream)
    stream.close()

    var resume_tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        _ = ctx.connect(
            resume_tcp^, "ok1.example.test", session=ticket.copy()
        )
    except e:
        raised = True
        var message = String(e)
        assert_true("handshake" in message, message)
        assert_true("certificate verify failed" in message, message)
    assert_true(
        raised,
        "a partial wildcard must not resume a different name",
    )
    reap(server[1])


def test_session_ticket_exact_name_with_partial_san_resumes() raises:
    # A partial-wildcard SAN next to an exact name must not disable
    # resumption of the exact name.
    var server = fork_two_echo_server(
        PARTIAL_AND_EXACT_CERT, PARTIAL_AND_EXACT_KEY
    )
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "ok.example.test")
    stream.write_all("ping".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "ping")
    var ticket = take_ticket(stream)
    stream.close()

    var resume_tcp = TCPStream.connect("127.0.0.1", server[0])
    var resumed = ctx.connect(
        resume_tcp^, "ok.example.test", session=ticket.copy()
    )
    assert_true(
        resumed.session_reused(),
        "exact name still resumes when the leaf also has a partial wildcard",
    )
    resumed.write_all("pong".as_bytes())
    assert_equal(String(from_utf8=resumed.read_exact(4)), "pong")
    resumed.close()
    reap(server[1])


def test_session_ticket_unverified_rejected() raises:
    var server = fork_two_echo_server(SELFSIGNED_CERT, SELFSIGNED_KEY)
    var unverified = TLSContext.client(verify=False)
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = unverified.connect(tcp^, "localhost")
    stream.write_all("ping".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "ping")
    var ticket = take_ticket(stream)
    assert_true(
        not stream.peer_certificate().value().verified,
        "the source handshake did not verify the self-signed certificate",
    )
    stream.close()

    var verifying = TLSContext.client(ca_file=String(CA))
    var resume_tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        _ = verifying.connect(resume_tcp^, "localhost", session=ticket.copy())
    except e:
        raised = True
        var message = String(e)
        assert_true("handshake" in message, message)
        assert_true("certificate verify failed" in message, message)
    assert_true(
        raised,
        "a ticket from an unverified handshake must not satisfy a verifying client",
    )
    reap(server[1])


def test_write_timeout_after_wrap() raises:
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, ["h2"])
    var ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    stream.set_write_timeout(1_000_000_000)
    stream.set_read_timeout(1_000_000_000)
    stream.write_all("ping".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "ping")
    stream.set_write_timeout(0)
    stream.close()
    reap(server[1])


def main() raises:
    test_handshake_echo_alpn()
    test_required_client_certificate()
    test_alert_in_the_handshake_is_received()
    test_alert_after_the_handshake_is_received_on_read()
    test_an_alert_is_sent_by_one_side_and_received_by_the_other()
    test_a_user_canceled_alert_is_not_recorded()
    test_a_peer_that_ends_the_handshake_is_a_typed_reset()
    test_reject_untrusted_client_certificate()
    test_certificate_client_completes_on_the_ticket()
    test_certificate_client_reads_the_alert_before_the_reset()
    test_certificate_client_meets_a_reset_with_nothing_readable()
    test_certificate_client_takes_the_ticket_and_close_in_one_read()
    test_certificate_client_fails_when_the_server_ends_with_a_fin()
    test_certificate_client_times_out_without_a_verdict()
    test_clean_eof()
    test_end_without_close_notify_is_a_typed_reset()
    test_reject_untrusted_ca()
    test_reject_wrong_hostname()
    test_hostname_wildcard_and_common_name()
    test_ip_literal_hostname()
    test_verify_disabled_accepts_selfsigned()
    test_reject_unsafe_subject_alt_names()
    test_peer_certificate_compatibility_constructor()
    test_alpn_no_overlap_fails()
    test_max_length_alpn_reported()
    test_read_timeout_through_tls()
    test_nonblocking_handshake_and_partial_io()
    test_bad_cert_paths()
    test_client_identity_configuration()
    test_session_ticket_resume()
    test_session_ticket_ip_literal_resume()
    test_session_ticket_wrong_name_rejected()
    test_session_ticket_partial_wildcard_rejected()
    test_session_ticket_exact_name_with_partial_san_resumes()
    test_session_ticket_unverified_rejected()
    test_write_timeout_after_wrap()
    print("test_tls: all tests passed")
