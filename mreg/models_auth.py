from django.contrib.auth.models import AbstractUser


class User(AbstractUser):

    _group_list = None

    @property
    def group_list(self):
        if self._group_list is None:
            self._group_list = list(self.groups.values_list('name', flat=True))
        return self._group_list
