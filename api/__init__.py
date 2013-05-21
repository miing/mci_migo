# Bit of surgery on piston internals, this fixes
# https://github.com/simplejson/simplejson/issues/37

import json
import simplejson

from piston.utils import Mimer
from piston import emitters

emitters.simplejson = json

Mimer.unregister(simplejson.loads)
Mimer.register(json.loads, ('application/json',))


# Another bit to please django-piston
from django.http import HttpResponse

HttpResponse._get_content = HttpResponse.content.fget
