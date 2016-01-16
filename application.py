
""" Микро-сервис для аутентификации

"""

from envi import SuitApplication
from controllers import UiController, ApiController


application = SuitApplication()
application.route("/", UiController)
application.route("/<action>/", UiController)
application.route_static("static", "/var/www/static/")

application.route("/api/<action>/", ApiController)


