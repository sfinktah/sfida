def static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        setattr(func, '__static_vars__', kwargs)
        return func
    return decorate
