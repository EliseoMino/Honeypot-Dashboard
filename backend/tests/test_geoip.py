from honeypot_backend.geoip import CountryLookup


def test_local_country_lookup_returns_code_and_name(tmp_path, monkeypatch) -> None:
    database = tmp_path / "country.mmdb"
    database.write_bytes(b"fixture")

    class Reader:
        def get(self, _address):
            return {"country": {"iso_code": "AR", "names": {"en": "Argentina"}}}

        def close(self):
            pass

    class MaxMind:
        @staticmethod
        def open_database(_path):
            return Reader()

    monkeypatch.setitem(__import__("sys").modules, "maxminddb", MaxMind)
    lookup = CountryLookup(database)
    assert lookup.lookup("203.0.113.1") == {
        "country_code": "AR",
        "country_name": "Argentina",
    }
    lookup.close()


def test_missing_database_and_address_are_gracefully_unavailable(tmp_path) -> None:
    lookup = CountryLookup(tmp_path / "missing.mmdb")
    assert lookup.lookup("203.0.113.1") == {"country_code": None, "country_name": None}
    assert CountryLookup(None).lookup("203.0.113.1") == {
        "country_code": None,
        "country_name": None,
    }
