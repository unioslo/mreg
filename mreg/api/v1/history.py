import json

from django.core.exceptions import ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import Model
from django.forms import model_to_dict

from mreg.models import History


class DjangoJSONModelEncoder(DjangoJSONEncoder):

    def default(self, o):
        return model_to_dict(o)


class HistoryLog:

    def save_log(self, action, serializer, data, orig_data=None):
        if serializer.Meta.model == self.model:
            model_id = serializer.data['id']
            name = serializer.data['name']
        else:
            obj = data.get(self.foreign_key_name,
                           serializer.data.get(self.foreign_key_name, None))
            if isinstance(obj, self.model):
                pass
            elif isinstance(obj, int):
                obj = self.model.objects.get(id=obj)
            elif obj is None:
                return
            model_id = obj.id
            name = obj.name
        self.manipulate_data(action, serializer, data, orig_data)
        if action == 'update':
            data = {'current_data': orig_data, 'update': data}
        model = serializer.Meta.model.__name__
        json_data = self.get_jsondata(data)
        history = History(user=self.request.user,
                          resource=self.log_resource,
                          name=name,
                          model_id=model_id,
                          model=model,
                          action=action,
                          data=json_data)

        # We should never fail at performing a clean on the testdata itself.
        try:
            history.full_clean()
        except ValidationError as e:  # pragma: no cover
            print(e)
            return
        history.save()

    @staticmethod
    # Must implement in own inherited class
    def manipulate_data(action, serializer, data, orig_data):
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
                "id": str(instance.id),
                "name": instance.name}
        model = instance.__class__.__name__
        action = method.__name__
        history = History(user=self.request.user,
                          resource=self.log_resource,
                          name=self.object.name,
                          model_id=self.object.id,
                          model=model,
                          action=action,
                          data=data)

        # We should never fail at performing a clean on the testdata itself.
        try:
            history.full_clean()
        except ValidationError as e:  # pragma: no cover
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
