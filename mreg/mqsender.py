import json
import ssl
import time
from datetime import datetime, timezone

import pika
from django.conf import settings
from pika.exceptions import (AMQPConnectionError, ConnectionClosedByBroker,
                             StreamLostError)


class MQSender:

    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(MQSender, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        self.mq_channel = None
        self.mq_id : int = time.time_ns()//1_000_000

        # Check the configuration
        config = getattr(settings, 'MQ_CONFIG', None)

        # We accept an empty configuration, this disables the MQ
        if config is None:
            return
        
        # However, if we have a configuration, it must be a dictionary,
        # and it must contain the keys host, username, password, and exchange
        if not isinstance(config, dict):
            raise ValueError('MQ_CONFIG must be a dictionary')
        
        for key in ['host', 'username', 'password', 'exchange']:
            if key not in config:
                raise ValueError(f'MQ_CONFIG must contain the key {key}')


    def send_event(self, obj, routing_key):
        config = getattr(settings, 'MQ_CONFIG', None)
        if config is None:
            return

        # Add an id property to the event
        obj['id'] = self.mq_id
        self.mq_id += 1

        # Add a timestamp to the event
        local_time = datetime.now(timezone.utc).astimezone()
        obj['timestamp'] = local_time.isoformat()

        for retry in range(10):
            if self.mq_channel is None or self.mq_channel.connection.is_closed:
                credentials = pika.credentials.PlainCredentials(
                    username=config['username'],
                    password=config['password'],
                )
                ssl_options = None
                if config.get('ssl', False):
                    ssl_context = ssl.create_default_context()
                    ssl_options = pika.SSLOptions(ssl_context, config['host'])
                connection_parameters = pika.ConnectionParameters(
                    host=config['host'],
                    credentials=credentials,
                    ssl_options = ssl_options,
                    virtual_host = config.get('virtual_host','/'),
                )
                try:
                    connection = pika.BlockingConnection(connection_parameters)
                    self.mq_channel = connection.channel()
                    if config.get('declare',False):
                        self.mq_channel.exchange_declare(
                            exchange=config['exchange'],
                            exchange_type='topic'
                        )
                except AMQPConnectionError:
                    continue

            try:
                self.mq_channel.basic_publish(
                    exchange=config['exchange'],
                    routing_key=routing_key,
                    body=json.dumps(obj),
                    properties=pika.BasicProperties(content_type="application/json"),
                )
                break
            except (ConnectionClosedByBroker, StreamLostError):
                self.mq_channel = None
