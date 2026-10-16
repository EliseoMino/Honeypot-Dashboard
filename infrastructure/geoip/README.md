# Optional offline GeoIP database

Place a licensed MaxMind GeoLite2 Country database here as
`GeoLite2-Country.mmdb`. The backend reads it locally; observed addresses are
not sent to a GeoIP service. The file is deliberately excluded from version
control. Create a MaxMind account, accept the applicable GeoLite terms and use
the database download/update process documented by MaxMind. Replace the file
with a current release and restart the backend to pick it up.

Without the database, country fields are `null` and the dashboard omits flags.
Country is approximate network context, not a physical location or proof of
origin. VPNs, proxies, mobile networks, and address reassignment can make it
incorrect. Reserved and private addresses have no country result.
