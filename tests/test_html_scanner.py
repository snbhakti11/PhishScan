import unittest
from bs4 import BeautifulSoup
from phishscan.html_scanner import analyze_forms


class TestHtmlScanner(unittest.TestCase):
    def test_no_forms(self):
        html = "<html><head></head><body><p>No forms here</p></body></html>"
        soup = BeautifulSoup(html, "html.parser")
        res = analyze_forms(soup, "https://example.com")
        self.assertEqual(res["form_count"], 0)
        self.assertEqual(res["login_forms"], [])

    def test_login_form_detection(self):
        html = '''
        <html><body>
        <form action="/login" method="post">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="hidden" name="csrf_token" value="abc" />
        </form>
        </body></html>
        '''
        soup = BeautifulSoup(html, "html.parser")
        res = analyze_forms(soup, "https://example.com")
        self.assertEqual(res["form_count"], 1)
        self.assertEqual(len(res["login_forms"]), 1)
        form = res["login_forms"][0]
        self.assertTrue(form["has_password"])
        self.assertTrue(any("csrf" in r.lower() or "token" in r.lower() for r in form["reasons"]))


if __name__ == '__main__':
    unittest.main()
