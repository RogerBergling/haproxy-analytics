from __future__ import annotations

import ipaddress
import unittest

from haproxy_analytics.privacy import (
    domain_matches,
    domain_only_path,
    host_from_url,
    is_internal_ip,
    mask_ip,
    mask_text_ips,
    normalize_domain,
    normalize_host,
)


class PrivacyTests(unittest.TestCase):
    def test_non_global_ipv4_is_masked(self) -> None:
        self.assertTrue(is_internal_ip("192.0.2.10"))
        self.assertEqual(mask_ip("192.0.2.10"), "192.0.x.x")
        self.assertEqual(mask_ip("198.51.100.20"), "198.51.x.x")
        self.assertEqual(mask_ip("203.0.113.30"), "203.0.x.x")
        self.assertEqual(mask_ip("127.0.0.1"), "127.0.x.x")

    def test_documentation_ipv4_is_masked(self) -> None:
        self.assertTrue(is_internal_ip("192.0.2.10"))
        self.assertEqual(mask_ip("192.0.2.10"), "192.0.x.x")

    def test_public_ipv4_is_unchanged(self) -> None:
        self.assertFalse(is_internal_ip("8.8.8.8"))
        self.assertEqual(mask_ip("8.8.8.8"), "8.8.8.8")

    def test_internal_ipv6_is_masked(self) -> None:
        self.assertTrue(is_internal_ip("fd00:1234::1"))
        self.assertEqual(mask_ip("fd00:1234::1"), "fd00:1234::x")
        self.assertEqual(mask_ip("2001:db8::1"), "2001:db8::x")
        self.assertEqual(mask_ip("::1"), "::x")

    def test_public_ipv6_is_unchanged(self) -> None:
        self.assertFalse(is_internal_ip("2001:4860:4860::8888"))
        self.assertEqual(mask_ip("2001:4860:4860::8888"), "2001:4860:4860::8888")

    def test_invalid_value_is_returned(self) -> None:
        self.assertFalse(is_internal_ip("not-an-ip"))
        self.assertEqual(mask_ip("not-an-ip"), "not-an-ip")

    def test_configured_networks_are_masked_with_their_prefix(self) -> None:
        networks = (
            ipaddress.ip_network("192.0.0.0/8"),
            ipaddress.ip_network("172.0.0.0/8"),
        )
        self.assertEqual(mask_ip("192.0.2.10", networks), "192.x.x.x")
        self.assertEqual(mask_ip("172.0.0.5", networks), "172.x.x.x")
        self.assertEqual(mask_ip("8.8.8.8", networks), "8.8.8.8")
        self.assertEqual(
            mask_text_ips("http://192.0.2.10/admin", networks),
            "http://192.x.x.x/admin",
        )

    def test_configured_networks_work_without_non_global_masking(self) -> None:
        networks = (ipaddress.ip_network("192.0.0.0/8"),)
        self.assertEqual(
            mask_ip("192.0.2.10", networks, mask_non_global=False),
            "192.x.x.x",
        )
        self.assertEqual(
            mask_ip("198.51.100.20", networks, mask_non_global=False),
            "198.51.100.20",
        )

    def test_full_mask(self) -> None:
        networks = (
            ipaddress.ip_network("192.0.0.0/8"),
            ipaddress.ip_network("172.0.0.0/8"),
        )
        self.assertEqual(mask_ip("192.0.2.10", networks, full=True), "x.x.x.x")
        self.assertEqual(mask_ip("172.0.0.5", networks, full=True), "x.x.x.x")
        self.assertEqual(mask_ip("8.8.8.8", networks, full=True), "8.8.8.8")
        self.assertEqual(mask_ip("2001:db8::1", full=True), "x:x:x:x:x:x:x:x")

    def test_internal_ip_in_text_is_masked(self) -> None:
        self.assertEqual(
            mask_text_ips("http://192.0.2.20/admin"),
            "http://192.0.x.x/admin",
        )
        self.assertEqual(
            mask_text_ips("http://[fd00:1234::1]:8080/admin"),
            "http://[fd00:1234::x]:8080/admin",
        )
        self.assertEqual(mask_text_ips("http://8.8.8.8/admin"), "http://8.8.8.8/admin")

    def test_normalize_domain(self) -> None:
        self.assertEqual(normalize_domain("*.Example.COM."), "example.com")
        self.assertEqual(normalize_domain(".example.org"), "example.org")
        self.assertEqual(normalize_domain("münchen.example"), "xn--mnchen-3ya.example")
        with self.assertRaises(ValueError):
            normalize_domain("https://example.com")

    def test_domain_matching_is_exact_or_subdomain(self) -> None:
        domains = ("example.com", "example.org")
        self.assertTrue(domain_matches("example.com", domains))
        self.assertTrue(domain_matches("app.example.com", domains))
        self.assertTrue(domain_matches("APP.EXAMPLE.COM:443", domains))
        self.assertFalse(domain_matches("badexample.com", domains))
        self.assertFalse(domain_matches("example.com.evil", domains))
        self.assertFalse(domain_matches("-", domains))

    def test_host_from_url(self) -> None:
        self.assertEqual(host_from_url("https://app.example.com/path"), "app.example.com")
        self.assertEqual(host_from_url("http://app.example.com:8080/path"), "app.example.com")
        self.assertEqual(host_from_url("//app.example.com/path"), "app.example.com")
        self.assertEqual(host_from_url("/relative/path"), "")

    def test_domain_only_path(self) -> None:
        self.assertEqual(
            domain_only_path("sendpass.example.com", "/?SECRET"),
            "sendpass.example.com/",
        )
        self.assertEqual(
            domain_only_path("sendpass.example.com", "https://sendpass.example.com/?SECRET"),
            "https://sendpass.example.com/",
        )
        self.assertEqual(
            domain_only_path("sendpass.example.com", "http://sendpass.example.com/path?q=1"),
            "http://sendpass.example.com/",
        )

    def test_normalize_host(self) -> None:
        self.assertEqual(normalize_host("App.Example.COM.:443"), "app.example.com")
        self.assertEqual(normalize_host("[2001:db8::1]:443"), "[2001:db8::1]")
        self.assertEqual(normalize_host("MÜNCHEN.example"), "xn--mnchen-3ya.example")
        self.assertEqual(normalize_host("bad host"), "")


if __name__ == "__main__":
    unittest.main()
