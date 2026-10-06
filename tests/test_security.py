"""Негативные security-тесты (TC-03, TC-04) + проверка авторизации.
Запуск:  TARGET=secure python -m unittest -v tests/test_security.py
         TARGET=vulnerable python -m unittest -v tests/test_security.py  (ожидаемо падает)
"""
import importlib.util
import os
import unittest

TARGET = os.environ.get("TARGET", "secure")
os.environ.setdefault("API_KEY", "test-key")
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", TARGET, "app.py")
spec = importlib.util.spec_from_file_location("target_app", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.c = mod.app.test_client()

    def test_tc03_sqli_in_query(self):
        """TC-03: SQL Injection через GET ?name= не должна возвращать все записи."""
        self.c.post("/api/users", json={"name": "alice", "email": "a@x.com"})
        r = self.c.get("/api/users", query_string={"name": "zzz%' OR 1=1 --"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), [], "SQLi вернула данные")

    def test_tc03_sqli_in_body(self):
        """TC-03: SQLi в теле POST блокируется валидацией (400)."""
        r = self.c.post("/api/users", json={"name": "x'); DROP TABLE users;--", "email": "a@x.com"})
        self.assertEqual(r.status_code, 400)

    def test_tc04_xss_not_executed(self):
        """TC-04: <script> не попадает в HTML в неэкранированном виде."""
        self.c.post("/api/users", json={"name": "<script>alert(1)</script>", "email": "a@x.com"})
        html = self.c.get("/users").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_delete_requires_auth(self):
        """A01: DELETE без ключа -> 401."""
        self.assertEqual(self.c.delete("/api/users/1").status_code, 401)

    def test_delete_with_key(self):
        r = self.c.delete("/api/users/1", headers={"X-API-Key": os.environ["API_KEY"]})
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()
