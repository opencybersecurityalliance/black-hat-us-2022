import json
import yaml
import logging
import os, os.path
import copy

import openc2
from kestrel.session import Session
from jinja2 import Template

FORMAT = '%(asctime)-15s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)

from kestrel_datasource_stixshifter.config import ENV_VAR_PREFIX

from oc2 import custom

CMD_PAIRS = {"investigate": [],
             "query": []}
#Kestrel some new fields in OC2
# args: huntargs
# args: returnvars
#  should these be moved into actuator.x-kestrel-actuator.args
# actuator.x-kestrel-actuator.huntbook
# actuator.x-kestrel-actuator.huntsteps
# actuator.x-kestrel-actuator.template (what conversion format for huntsteps)

class KestrelHuntbookActuator(object):
    """Perform an investigation using Huntbooks implemented in the Kestrel Threat Hunting Language
    """
    def __init__(self, config):
        self.config = {}
        with open(config, 'r') as fd:
            self.config = yaml.load(fd, yaml.SafeLoader)

    def getResponseType(self, cmd):
        if not cmd.get("args"):
            self.responseType = "complete"
            return
        if not cmd["args"].get("response_requested"):
            self.responseType = "complete"
            return

        self.responseType = cmd["args"]["response_requested"]

    def canHandle(self, cmd):
        if cmd.get("action") == 'query' or cmd.get("action") == 'investigate':
            return True

        #FIXME: check for targets supported in huntbooks
        return False

    def _getHuntbookInfo(self):
        with open("huntbooks.conf") as f:
            d = json.load(f)
        return d

    def _query(self, cmd):
        if self.responseType != 'complete':
            return openc2.v10.Response(status=400, status_text="Bad request", results={})
        if not cmd.get("target") or not cmd["target"].get("features"):
            return openc2.v10.Response(status=200, status_text="", results={})

        results = {}
        for f in cmd["target"].get("features"):
            if f == "version":
                results["versions"] = ["1.0"]
            elif f == "profiles":
                results["profiles"] = ["kestrel"]
            elif f == "rate_limit":
                results["rate_limit"] = 30
            elif f == "pairs":
                results["pairs"] = CMD_PAIRS

        if "features" in cmd["target"]:
            results["x-kestrel"] = self._getHuntbookInfo()
        return openc2.v10.Response(status=200, status_text="", results=results)

    def process(self, cmd, **kwargs):
        self.getResponseType(cmd)
        if self.responseType == 'ack':
          # send Ack immediately
          #FIXME: unless it's query command
          #openc2.v10.Response(status=102, status_text="Ack", results={})
          pass

        if not self.canHandle(cmd):
          if self.responseType != 'none':
            return openc2.v10.Response(status=501, status_text="Not implemented", results={})

        if cmd.get("action") == "query":
          return self._query(cmd)

        try:
            return openc2.v10.Response(status=200, status_text="complete", results=self._investigate(cmd, **kwargs))
        except Exception as e:
            return openc2.v10.Response(status=500, status_text=str(e))

    def _investigate(self, cmd, **kwargs):
        basedir = self.config.get('huntflowdir', os.path.join(os.path.dirname(__file__), 'huntflows'))
        fullpath = os.path.abspath(os.path.join(basedir, cmd.actuator.huntbook))
        if not os.path.isabs(basedir):
            basedir = os.path.join(os.getcwd(), basedir)
        huntflow = ''
        logger.info(f"Trying to load huntfile: {fullpath}")
        # Check to see if we're trying to break out of a huntbook root
        # Scan for relevant huntbooks
        # Load and template (using the file extension) the appropriate one
        if basedir == os.path.commonpath((basedir, fullpath)):
            bn = os.path.basename(fullpath)
            dirname = os.path.dirname(fullpath)
            for huntfile in os.listdir(dirname):
                if not huntfile.startswith(bn):
                    continue
                if not huntfile.endswith((".jhb", ".hb", ".phb", ".ipynb")):
                    continue
                with open(os.path.join(dirname, huntfile), 'r') as hf:
                    logger.info(f"Loading huntbook: {huntfile}")
                    huntflow = hf.read()
                break
            if len(huntflow) == 0:
                logger.error("Did not load huntbook")
        else:
            logger.error('Suspected attack on huntbooks: "{0}". Ignoring'.format(cmd.actuator.huntbook))

        # TODO Are there any safety checks we need to do here first?
        huntsteps = ''
        huntargs = copy.copy(self.config.get('default_huntargs', {}))
        try:
            huntargs.update(cmd.args.huntargs)
        except Exception as e:
            logger.error(f"Error updating hunt args {e}")
        # TODO update any args (start_time, end_time, duration)
        huntargs.update(cmd.target)
        logger.debug(f"Hunt variables {huntargs}")
        try:
            # TODO see why OC2 doesn't return an empty list or None here
            huntsteps = '\n'.join(cmd.actuator.huntsteps)
            huntsteps = self.__template(huntsteps, huntargs, cmd.actuator.template)
        except AttributeError as e:
            logger.debug(f"No huntsteps: {e}")

        #mvle FIXME - move logic to __template 
        if huntfile.endswith('.jhb'):
            # Jinja2 Templated Huntbook
            huntflow = self.__template(huntflow, huntargs, 'jinja2')
        elif huntfile.endswith(".phb"):
            # Python Templated Huntbook
            huntflow = self.__template(huntflow, huntargs, 'python')
        elif huntfile.endswith(".ipynb"):
            # iPython Notebook (Kestrel Kernel)
            # Could still assume this is a jinja2 template. ipynb are just json
            logger.error("Not supporting iPython Notebooks yet")
            raise Exception("Unsupported huntbook type ipynb")
        elif huntfile.endswith(".hb"):
            # Raw Huntbook
            huntflow = huntflow
        else:
            raise Exception("Unknown or unhandled huntbook type")
        return self.__execute(cmd, huntflow)

    def __execute(self, cmd, huntflow, **kwargs):
        if cmd.action != 'investigate':
            logger.error("Unsupported action {0}. Must be investigate.".format(cmd.action))
            return None
        #logger.debug(f"Huntflow:\n{huntflow}")
        with Session() as session:
            session.execute(huntflow)
            kvars = session.get_variable_names()
            returnval = {var:session.get_variable(var) for var in cmd.args.returnvars if var in kvars}
        return returnval
    
    @staticmethod
    def __template(huntflow, huntargs, template):
        """Generic templating for hunt steps and huntbooks"""
        if template == 'jinja2':
            j2_template = Template(huntflow)
            return j2_template.render(huntargs)
        elif template == 'python':
            return huntflow.format(**huntargs)
        return huntflow


if __name__ == '__main__':
    act = KestrelHuntbookActuator('investigate.yml')
