#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    from dotenv import load_dotenv
    from mreg.env import envvar

    load_dotenv(os.getenv("MREG_DOTENV_PATH"), override=envvar("MREG_DOTENV_OVERRIDE", False))

    # use default settings module if dotenv doesn't override it
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mregsite.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)
