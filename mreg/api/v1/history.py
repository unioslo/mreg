import json

from django.forms import model_to_dict
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import Model


class DjangoJSONModelEncoder(DjangoJSONEncoder):

    def default(self, o):

        if isinstance(o, Model):
            return model_to_dict(o)

        return super().default(o)


class HistoryLog:

    @staticmethod
    # Must implement in own inherited class
    def save_log(change_type, serializer, data, orig_data=None):
        pass

    @staticmethod
    def get_jsondata(data):
        return json.dumps(data, cls=DjangoJSONModelEncoder)

    def save_log_create(self, serializer):
        self.save_log("create", serializer, serializer.validated_data)

    def save_log_update(self, serializer):
        self.save_log("update", serializer, serializer.validated_data, orig_data=self.orig_data)

    def perform_create(self, serializer, **kwargs):
        super().perform_create(serializer)
        self.save_log_create(serializer)

    def perform_update(self, serializer):
        # Make sure to get the original data before serializer.save()
        if not hasattr(self, 'orig_data'):
            self.orig_data = self.get_serializer(self.get_object()).data
        super().perform_update(serializer)
        self.save_log("update", serializer, serializer.validated_data, orig_data=self.orig_data)

    def perform_destroy(self, instance):
        serializer = self.get_serializer(instance)
        # Keep copy before it is destroyed
        data = serializer.data.copy()
        super().perform_destroy(instance)
        self.save_log("destroy", serializer, data)
