import unittest
from urllib.parse import parse_qs, urlsplit

import requests

from gateway.main import normalize_request_target


class NormalizeRequestTargetTests(unittest.TestCase):
    def test_repairs_utf8_query_mojibake(self) -> None:
        target = "/api/Trn/GetBillOfLadingByPlaque?plaqueId=15Ø¹276&plaqueSn=36"

        normalized = normalize_request_target(target)
        parsed = urlsplit(normalized)
        query = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}

        self.assertEqual(normalized, "/api/Trn/GetBillOfLadingByPlaque?plaqueId=15ع276&plaqueSn=36")
        self.assertEqual(query["plaqueId"], "15ع276")

        with requests.Session() as session:
            prepared = session.prepare_request(
                requests.Request("GET", "http://example.test" + parsed.path, params=query)
            )

        self.assertIn("plaqueId=15%D8%B9276", prepared.url)
        self.assertIn("plaqueSn=36", prepared.url)

    def test_keeps_percent_encoded_utf8_untouched(self) -> None:
        target = "/api/Trn/GetBillOfLadingByPlaque?plaqueId=15%D8%B9276&plaqueSn=36"

        normalized = normalize_request_target(target)

        self.assertEqual(normalized, target)


if __name__ == "__main__":
    unittest.main()
