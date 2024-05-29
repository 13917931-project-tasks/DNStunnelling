spicy_add_analyzer(
    NAME dnstunnelling
    PACKAGE_NAME DNStunnelling
    SOURCES dnstunnelling.spicy dnstunnelling.evt zeek_dnstunnelling.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
