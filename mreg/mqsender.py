from django.conf import settings

from datetime import datetime, timezone;
import json
import os
import pika
import random
import ssl
import string
import time

from pika.exceptions import (ConnectionClosedByBroker, StreamLostError, AMQPConnectionError)


class MQSender(object):

	def __new__(cls):
		if not hasattr(cls, 'instance'):
			cls.instance = super(MQSender, cls).__new__(cls)
		return cls.instance

	def __init__(self):
		self.mq_channel = None
		self.mq_id : int = time.time_ns()//1_000_000

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
				if config.get('ssl',False):
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
						self.mq_channel.exchange_declare(exchange=config['exchange'], exchange_type='topic')
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
