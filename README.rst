SimpleReverseProxy
=================
a simple reverse proxy

Quickstart
----------

.. code-block:: python

    usage: client [-h] [--ip IP] [--port PORT] [--upstream_ip UPSTREAM_IP]
              [--upstream_port UPSTREAM_PORT] [--listen_ip LISTEN_IP]
              [--listen_port LISTEN_PORT] [--password PASSWORD]
              [--method METHOD]

    SimpleReverseProxy Client

    optional arguments:
      -h, --help            show this help message and exit
      --ip IP               set server ip
      --port PORT           set server port
      --upstream_ip UPSTREAM_IP
                            set upstream ip
      --upstream_port UPSTREAM_PORT
                            set upstream port
      --listen_ip LISTEN_IP
                            set listen ip
      --listen_port LISTEN_PORT
                            set listen port
      --password PASSWORD   the password used to connect
      --method METHOD       the encrypt method used to connect


.. code-block:: python

    usage: server [-h] [--ip IP] [--port PORT] [--password PASSWORD]
              [--method METHOD]

    SimpleReverseProxy Server

    optional arguments:
      -h, --help           show this help message and exit
      --ip IP              set server ip
      --port PORT          set server port
      --password PASSWORD  the password used to connect
      --method METHOD      the encrypt method used to connect


© 2017-? wwqgtxx
