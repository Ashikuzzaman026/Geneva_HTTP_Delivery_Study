import argparse
import json
import os
from plugins.plugin_client import ClientPlugin
from geneva_healthcheck import measure

class FileCheckClient(ClientPlugin):
    name="filecheck"
    def __init__(self,args):
        ClientPlugin.__init__(self)
        self.args=args
    @staticmethod
    def get_args(command):
        args=ClientPlugin.get_args(command)
        parser=argparse.ArgumentParser(description="Endpoint-only file verification",allow_abbrev=False)
        parser.add_argument("--probe-host",default="benign.example")
        parser.add_argument("--transfer-timeout",type=float,default=10)
        custom,_=parser.parse_known_args(command); args.update(vars(custom))
        return args
    def run(self,args,logger,engine=None):
        result=measure(args["server"],args["port"],args["probe_host"],args["transfer_timeout"])
        
        folder=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                            args["output_directory"],"endpoint")
        os.makedirs(folder,exist_ok=True)
        path=os.path.join(folder,args["environment_id"]+".json")
        with open(path,"w") as f: json.dump(result,f,indent=2,sort_keys=True)
        logger.info("ENDPOINT_RESULT %s",json.dumps(result,sort_keys=True))
        return 2000 if result["diagnosis"]["delivery_verified"] else -400
