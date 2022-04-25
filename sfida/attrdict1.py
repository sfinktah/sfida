class SimpleAttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(SimpleAttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

AttrDict = SimpleAttrDict
