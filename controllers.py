""" Контроллеры сервиса """

from envi import Controller, Request, template


class UiController(Controller):
    """ Контроллер """
    default_action = "dashboard"

    @staticmethod
    @template("views.blog")
    def dashboard(request: Request, *args, **kwargs):
        """
        :param request:
        :param args:
        :param kwargs:
        """
        return {
            "hello": "world"
        }

    @staticmethod
    @template("views.blog")
    def new(request: Request, *args, **kwargs):
        """
        :param request:
        :param args:
        :param kwargs:
        """
        return {
            "categories": ApiController.get_categories(request),
            "hello": "world"
        }

    @staticmethod
    @template("views.blog")
    def edit(request: Request, *args, **kwargs):
        """
        :param request:
        :param args:
        :param kwargs:
        """
        return {
            "hello": "world"
        }


class ApiController(Controller):
    """ Контроллер для ajax-запросов """
    @staticmethod
    def get_categories(request: Request, *args, **kwargs):
        """ Возвращает список категорий/рубрик блога
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        return [
            {"id": 1, "name": "Первая категория"},
            {"id": 2, "name": "Вторая категория"},
            {"id": 3, "name": "Третья категория"}
        ]

    @staticmethod
    def tags(request: Request, *args, **kwargs):
        return [
            "первый", "второй", "третий", "четвертый", "пятый"
        ]

    @staticmethod
    def crop(request: Request, *args, **kwargs):
        import requests
        import json
        payload = {'img': request.get("img"), 'coords': json.dumps(request.get("coords")), "from_size": json.dumps(request.get("from_size"))}
        r = requests.post("http://z9img/crop", data=payload)
        if r.status_code == 200:
            return r.text
        else:
            return request.get("img")

    @staticmethod
    def upload(request: Request, *args, **kwargs):
        import requests
        import json
        payload = {'base64': request.get("img")}
        r = requests.post("http://z9s3/upload", data=payload)
        if r.status_code == 200:
            return json.loads(r.text).get("url")
        else:
            return request.get("img")