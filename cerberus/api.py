import json
from os import confstr_names

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
        return Response(content_type='application/json',
                        json=self.app.hello_world())


    @route("cerberus", "/api/switches", methods=['GET'])
    def switches(self, req, **kwargs):
        """ Test to see if dictionaries can be returned as json """
        return Response(content_type='application/json',
                        json=self.app.get_switches())

    @route("cerberus", "/api/push_config", methods=['PUT'])
    def push_new_config(self, req, **kwargs):
        """ Send new config to cerberus to load """
        args = {}
        try:
            # if req.body:
            #     args = json.loads(req.body.decode('utf-8'))
            return Response(content_type='application/json',
                            json=self.app.compare_new_config_with_stored_config(req.body))
        except:
            return Response(status=500,
                            json={"error": traceback.format_exc()})