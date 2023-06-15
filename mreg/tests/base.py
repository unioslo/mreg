"""Base class for Mreg tests."""

def clean_and_save(entity):
    entity.full_clean()
    entity.save()


