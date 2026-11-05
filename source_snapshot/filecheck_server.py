import argparse
from plugins.plugin_server import ServerPlugin
from geneva_healthcheck import make_server

class FileCheckServer(ServerPlugin):
    name="filecheck"
    def __init__(self,args):
        ServerPlugin.__init__(self)
        self.args=args
    @staticmethod
    def get_args(command):
        args=ServerPlugin.get_args(command)
        parser=argparse.ArgumentParser(description="Local reference-file HTTP server",allow_abbrev=False)
        parser.add_argument("--file-server-mode",default="normal",choices=["normal","truncate","corrupt","status503","delay"])
        parser.add_argument("--file-server-delay",type=float,default=0)
        custom,_=parser.parse_known_args(command);args.update(vars(custom))
        return args
    def run(self,args,logger):
        
        server=make_server(("0.0.0.0",int(args["port"])),args["file_server_mode"],args["file_server_delay"])
        logger.info("FILE_SERVER ready: reference-file HTTP service")
        try: server.serve_forever()
        finally: server.server_close()
