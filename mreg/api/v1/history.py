import json

from django.core.exceptions import ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import Model
from django.forms import model_to_dict

from mreg.models import History


class DjangoJSONModelEncoder(DjangoJSONEncoder):

    def default(self, o):

        if isinstance(o, Model):
            return model_to_dict(o)

        return super().default(o)


class HistoryLog:

    @staticmethod
    # Must implement in own inherited class
    def save_log(action, serializer, data, orig_data=None):
        pass

    @staticmethod
    def get_jsondata(data):
        return json.dumps(data, cls=DjangoJSONModelEncoder)

    def save_log_create(self, serializer):
        self.save_log("create", serializer, serializer.validated_data)

    def save_log_update(self, serializer):
        self.save_log("update", serializer, serializer.validated_data, orig_data=self.orig_data)

    def save_log_m2m_alteration(self, method, instance):
        data = {"relation": self.m2m_field,
                "name": instance.name}
        model = instance.__class__.__name__
        action = method.__name__
        history = History(user=self.request.user,
                          resource=self.resource,
                          name=self.object.name,
                          model_id=self.object.id,
                          model=model,
                          action=action,
                          data=data)
        try:
            history.full_clean()
        except ValidationError as e:
            print(e)
            return
        history.save()

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

    def perform_m2m_alteration(self, method, instance):
        super().perform_m2m_alteration(method, instance)
        self.save_log_m2m_alteration(method, instance)
