from flask import Blueprint
from app.models import Permission

main = Blueprint('main', __name__)

from . import errors, views


@main.app_context_processor
def inject_permission():
    return dict(Permission=Permission)
