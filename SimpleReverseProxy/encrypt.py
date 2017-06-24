#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from .encrypt0 import *

try:
    from .encrypt1 import init as init1

    init1()
except ImportError:
    pass
try:
    from .encrypt2 import init as init2

    init2()
except ImportError:
    pass

logger.info(ciphers)

default_cipher_name = "chacha20"
