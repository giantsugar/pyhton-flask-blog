from functools import wraps
from flask import abort
from flask_login import current_user
from .models import Permission


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        # 这个装饰器保证了返回函数的__name__属性不变
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
                # 如果当前用户的权限检查没有通过，则生成403错误
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# 参数直接输入管理员的权限数值，用来校验
def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)
