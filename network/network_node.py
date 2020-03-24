import socket
import binascii
import inspect

from network.discovery import run_detailed_scan
from mitm_service.mitm_service import MITMService
import mitm_service.protocol_filters as filters
import json


class NetworkNode:
    SUPPORTED_FILTERS = {
        'reassign_dns_results': filters.generate_dns_reassign_rule,
        'log_dns_requests': filters.generate_dns_log_rule,
        'redirect_ip_addresses': filters.generate_ip_redirect_rule
    }

    def __init__(self, interface, ip, mac, gateway_ip, gateway_mac, tags=None):
        self.interface = interface
        self.ip = ip
        self.mac = mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac

        self.tags = tags or {}

        self.mitm_service = MITMService(
            self.interface,
            self.ip,
            self.gateway_ip,
            self.mac,
            self.gateway_mac
        )

    @property
    def ip_bytes(self):
        return socket.inet_aton(self.ip)

    @property
    def mac_bytes(self):
        return binascii.unhexlify(self.mac.replace(':', ''))

    def fill_detailed_tags(self):
        detailed_tags = run_detailed_scan(self.ip)
        for key, value in detailed_tags.items():
            self.tags[key] = value

    def start_mitm(self):
        self.mitm_service.start_mitm()

    def stop_mitm(self):
        self.mitm_service.stop_mitm()

    def add_filter(self, *args, **kwargs):
        self.mitm_service.add_filter(*args, **kwargs)

    def remove_filter(self, index):
        self.mitm_service.remove_filter(index)

    def restore_traffic(self):
        self.mitm_service.l2_tunnel._packet_filters = []

    def to_json(self):
        json_repr = {
            'interface': self.interface,
            'ip': self.ip,
            'mac': self.mac,
            'gateway_ip': self.gateway_ip,
            'gateway_mac': self.gateway_mac,
            'tags': self.tags,
            'is_mitm_running': self.mitm_service.is_mitm_running
        }
        return json_repr

    def get_json_str(self):
        return json.dumps(self.to_json())

    def json_query_supported_filters(self):
        """
        Return a json of this node's supported filters of form:
        {
        filter_name:[filter_param_1, filter_param_2, ...],
        ...
        }
        :return: dict
        """
        response = {}
        for filter_name, filter_function in type(self).SUPPORTED_FILTERS.items():
            response[filter_name] = list(inspect.signature(filter_function).parameters)
        return response

    def json_query_active_filters(self):
        """
        Get the currently active filters on this node by index, in a json of the form:
        {
        0:  {
                'filter_name':'<name_of_filter>',
                'filter_args':{'arg_name_1': <arg_val_1>, 'arg_name_2': <arg_val_2>, ...}
            }
            ...
        }
        :return: dict
        """
        response = {}
        for i, filter_function in enumerate(self.mitm_service.l2_tunnel._packet_filters):
            response[i] = {
                'filter_name': filter_function.name,
                'filter_args': filter_function.keyword_arguments
            }
        return response

    def json_request_remove_filter(self, request):
        """
        Accepts a request json of form:
        {'filter_index': <index_of_filter>}
        :param request: the request json to process
        :return: error response as dict
        """
        filter_index = int(request['filter_index'])
        self.remove_filter(filter_index)
        return {'success': True}


    def json_add_rule(self, node_json_request):
        """
        Add rule requested by the submitted node_json_request
        :param node_json_request: json of the form:
            {
            filter_name: [filter_param_value_1, filter_param_value_2, ...],
            ...
            }
        :return:error response as dict
        """
        try:
            for filter_name, filter_args in node_json_request.items():
                filter_function = type(self).SUPPORTED_FILTERS[filter_name](**filter_args)
                self.add_filter(0, filter_function)
            return {'success': True}
        except Exception as e:
            error_response = {
                'error_code': str(e),
                'success': False
            }
            return error_response

    def __repr__(self):
        repr_str = "NetworkNode(ip={}, mac={}, tags={})".format(self.ip, self.mac, self.tags)
        return repr_str

    def __str__(self):
        return self.__repr__()
