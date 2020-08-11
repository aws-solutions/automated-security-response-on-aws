###############################################################################
#  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import os
import json
import uuid
import requests
import hashlib
from urllib.request import Request, urlopen
from datetime import datetime

SEND_METRICS = os.environ.get('sendAnonymousMetrics', 'No')
METRICS_ID = os.environ.get('metricsId', None)

class Metrics(object):

    event_type = ''
    def __init__(self, event):
        try:
            self.event_type = event.get('detail-type')
        except Exception as excep:
            print(excep)

    def get_metrics_from_finding(self, finding):
        try:
            id = METRICS_ID[23:]
            id_as_bytes = str.encode(id)
            hash_lib = hashlib.sha256()
            hash_lib.update(id_as_bytes)
            id = hash_lib.hexdigest()
        except Exception as excep:
            pass
        try:
            if finding is not None:
                metrics_data = {
                    'Id': id,
                    'generator_id': finding.get('GeneratorId'),
                    'type': finding.get('Title'),
                    'productArn': finding.get('ProductArn'),
                    'finding_triggered_by': self.event_type
                }
            else:
                metrics_data = {}
            return metrics_data
        except Exception as excep:
            print(excep)
            return {}

    def send_metrics(self, metrics_data):
        try:
            id = METRICS_ID[23:]
            id_as_bytes = str.encode(id)
            hash_lib = hashlib.sha256()
            hash_lib.update(id_as_bytes)
            id = hash_lib.hexdigest()
        except Exception as excep:
            pass
        try:
            if metrics_data is not None and SEND_METRICS.lower() == 'yes':
                usage_data = {'Solution': 'SO0111',
                              'Id': id,
                              'UUID': id,
                              'TimeStamp': str(datetime.utcnow().isoformat()),
                              'Data': metrics_data}
                url = 'https://metrics.awssolutionsbuilder.com/generic'
                req = Request(url, method='POST', data=bytes(json.dumps(
                    usage_data), encoding='utf8'), headers={'Content-Type': 'application/json'})
                rsp = urlopen(req)
                rspcode = rsp.getcode()
                return rspcode
            else:
                return
        except Exception as excep:
            print(excep)
        return
