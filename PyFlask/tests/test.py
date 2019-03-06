# import hashlib
#
# avatar_hash = hashlib.md5(
#                 '10@4'.encode('utf-8')).hexdigest()
# print(avatar_hash)
# print(8&255)
# import os
# print(os.environ.get('FLASKY_POSTS_PER_PAGE'))
# print(bool(None))
from flask import current_app

print(current_app.config['SECRET_KEY'])