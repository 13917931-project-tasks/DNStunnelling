# TODO: Use this file to optionally declare signatures activating your analyzer
# (instead of, or in addition to, using a well-known port).
#
# signature dpd_dnstunnelling {
#     ip-proto == udp
#     payload /^\x11\x22\x33\x44/ # TODO: Detect your protocol here.
#     enable "spicy_dnstunnelling"
# }
