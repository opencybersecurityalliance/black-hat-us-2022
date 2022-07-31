import json

import openc2
from openc2.v10 import Args

namespace = "x-kestrel"

@openc2.v10.CustomActuator(
    namespace,
    [
        # Name of the Huntbook to run
        ("huntbook", openc2.properties.StringProperty(required=False)),
        # Starting point for the hunt; variables to bind?
        ("huntsteps", openc2.properties.ListProperty(openc2.properties.StringProperty(), required=False)),
        # What template to use to pass in arguments (mainly for the huntsteps)
        ("template", openc2.properties.StringProperty())
    ]
)
class KestrelActuator(object):
    pass

@openc2.v10.CustomArgs(
    namespace, 
    list(Args._properties.items()) + [
        ("huntargs", openc2.properties.DictionaryProperty()),
        ("returnvars", openc2.properties.ListProperty(openc2.properties.StringProperty())),
    ]
)
class KestrelArgs(object):
    pass
