from ryu import cfg

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.StrOpt('topology-file', default=None, help='chirouter topology file'),
    cfg.StrOpt('host', default="localhost", help='chirouter host'),
    cfg.IntOpt('port', default=23320, help='chirouter port')
], group="chirouter")
