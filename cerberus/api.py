import json

from ryu.app.wsgi import ControllerBase, route
from webob import Response
import traceback

class api(ControllerBase):
    """ API front end for Cerberus.

        Builds on top of Ryu's built in wsgi to
        provide basic API endpoint for Cerberus
    """
    def __init__(self, req, link, data, **config):
        super(api, self).__init__(req, link, data, **config)
        self.app = data['cerberus_main']

    @route("cerberus", "/api/hello_world", methods=['GET'])
    def hello_world(self, req, **kwargs):
        """ Hello world test to test everything is working """
        self.app.logger.info(f"Hello world was called by:\t{req.host}")
        return Response(content_type='application/json',
                        json=self.app.hello_world())


    @route("cerberus", "/api/switches", methods=['GET'])
    def switches(self, req, **kwargs):
        """ Test to see if dictionaries can be returned as json """
        self.app.logger.info(f"Request for switches was called by:\t{req.host}")
        return Response(content_type='application/json',
                        json=self.app.get_switches())

    @route("cerberus", "/api/push_config", methods=['PUT'])
    def push_new_config(self, req, **kwargs):
        """ Send new config to cerberus to load """
        self.app.logger.info(f"A config update was sent in by:\t{req.host}")
        args = {}
        try:
            # if req.body:
            #     args = json.loads(req.body.decode('utf-8'))
            return Response(content_type='application/json',
                            json=self.app.push_new_config(req.body))
        except:
            return Response(status=500,
                            json={"error": traceback.format_exc()})


    @route("cerberus", "/api/get_config", methods=['GET'])
    def get_running_config(self, req, **kwargs):
        args = {}
        self.app.logger.info(f"Request for switches was called by:\t{req.host}")
        try:
            return Response(content_type='application/json',
                            json=self.app.get_running_config_file())
        except:
            return Response(status=500, json={"error": traceback.format_exc()})


    @route("cerberus", "/api/get_full_config", methods=['GET'])
    def get_full_config(self, req, **kwargs):
        self.app.logger.info(f"Request for full config was called by:\t{req.host}")
        try:
            return Response(content_type='application/json',
                            json=self.app.get_running_config())
        except:
            return Response(status=500, json={"error": traceback.format_exc()})