from datetime import datetime
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from markdown import markdown
import bleach
from flask import current_app, request, url_for
from flask_login import UserMixin, AnonymousUserMixin
from app.exceptions import ValidationError

from . import db, login_manager


class Permission:
    FOLLOW = 0x01
    # 关注用户
    COMMENT = 0x02
    # 评论
    WRITE_ARTICLES = 0x04
    # 写文章
    MODERATE_COMMENTS = 0x08
    # 协管员
    ADMINISTER = 0x80
    # 管理员


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)  # 普通整数，主键
    name = db.Column(db.String(64), unique=True)  # 不允许重复值
    default = db.Column(db.Boolean, default=False, index=True)  # 布尔值，默认值，创建索引
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    # 不加载记录，但提供加载记录的查询

    @staticmethod
    # 创建角色
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            # 历遍roles字典
            role = Role.query.filter_by(name=r).first()
            # 查询Role类里是否存在这种name的角色
            if role is None:
                # 如果Role类里面没有找到
                role = Role(name=r)
                # 则新建角色，以r的值为名字(其实是用户组的名字)
            role.permissions = roles[r][0]
            # 为该role的权限组分配值，从字典取值
            role.default = roles[r][1]
            # 为该role的默认权限组分配布尔值，默认是False
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    @staticmethod
    # 创建虚拟数据
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['CANGHAI_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            # 在创建新用户的时候，判断email有的情况下，如果avatar_hash为空
            self.avatar_hash = hashlib.md5(
                self.email.encode('utf-8')).hexdigest()
            # 则生成avatar_hash的值
        self.followed.append(Follow(followed=self))

    # 计算密码散列值
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    # 增加generate_confirmation_token方法，用来生成用户的id的加密签名
    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        # 先产生个Serializer类的实例，里面设置好密钥和过期时间
        return s.dumps({'confirm': self.id})
        # 返回一个加密签名

    def confirm(self, token):
        # 增加一个方法，接收一个
        s = Serializer(current_app.config['SECRET_KEY'])
        # 先产生个Serializer类的实例，里面设置好密钥
        try:
            data = s.loads(token)
        except:
            return False
            # try解析加密签名，如果不能返回False
        if data.get('confirm') != self.id:
            return False
            # 如果加密签名中的‘confirm’的值不等于用户id，返回False
        self.confirmed = True
        db.session.add(self)
        # 等于的话，用户的confirmed属性改为True，意思为确认过的账户
        return True
        # 检验令牌 检查令牌中的id和存储在current_user中的令牌是否匹配

    # 增加generate_reset_token方法，用来生成用户的id的加密签名
    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        # 先产生个Serializer类的实例，里面设置好密钥和过期时间
        return s.dumps({'reset': self.id})
        # 返回一个加密签名

    # 增加更改密码的方法，接受token加密签名，新密码
    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        # 产生实例s
        try:
            data = s.loads(token)
        except:
            return False
        # 试着解析加密签名，得到字典data，否则返回False
        if data.get('reset') != self.id:
            return False
        # 如果data字典中的reset的值不等于用户的id，返回False
        self.password = new_password
        # 否则，更新用户密码
        db.session.add(self)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.avatar_hash = hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        # 修改email后重新生成对应的avatar_hash值
        db.session.add(self)
        return True


    # can()方法检查用户的权限
    def can(self, permissions):
        return self.role is not None and \
               (self.role.permissions & permissions) == permissions
        # 检测对象的role属性不是None的同时，对象的权限数值和要求检验的数值符合

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)
        # 直接赋值管理员的权限数值，看是否符合要求

    # ping()方法刷新用户最后访问时间
    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    # 用户头像的生成 大小格式
    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        # 这一句就是让计算值缓存的关键，优先选数据库内的信息
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)
        # 最后一行返回一个完整的url地址
        # 一共由这几部分组成
        # url代表是http或者是https
        # hash对应不同的email地址生成的hash值
        # ?后面就是查询值，也就是参数的设置s代表size，d代表默认图片生成方式，r代表图片级别，就是适合几岁看
        # format则是将参数对应起来输入

    # 关注
    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        return self.followed.filter_by(
            followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        return self.followers.filter_by(
            follower_id=user.id).first() is not None

    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id == Post.author_id) \
            .filter(Follow.follower_id == self.id)

    # JSON 是 HTTP 请求和响应使用的传输格式,把文章转换成 JSON 格式的序列化字典
    def to_json(self):
        json_user = {
            'url': url_for('api.get_user', id=self.id, _external=True),
            'username': self.username,
            'member_since': self.member_since,
            'last_seen': self.last_seen,
            'posts': url_for('api.get_user_posts', id=self.id, _external=True),
            'followed_posts': url_for('api.get_user_followed_posts',
                                      id=self.id, _external=True),
            'post_count': self.posts.count()
        }
        return json_user
        # 所有url_for()方法都指定了参数 _external=True，这么做是为了生成完整的URL

    def generate_auth_token(self, expiration):
        s = Serializer(current_app.config['SECRET_KEY'],
                       expires_in=expiration)
        return s.dumps({'id': self.id}).decode('ascii')
        # generate_auth_token() 方法使用编码后的用户id字段值生成一个签名令牌

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])
        # verify_auth_token() 方法接受的参数是一个令牌，如果令牌可用就返回对应的用户

    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser
# 将login_manager.anonymous_user设为AnonymousUser类对象，实际上就是未登录状态的current_user


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    # 文章内容
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    # 时间戳，据现在多久
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # 外键，和users表相连
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        # 查询一共有生成了多少虚拟用户
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1, 5)),
                     timestamp=forgery_py.date.date(True),
                     author=u)
            # 将用户和所发的文章绑定了起来
            db.session.add(p)
            db.session.commit()
            # 生成虚拟数据

    @staticmethod
    # on_changed_body 函数 把body字段中的文本渲染成HTML格式，结果保存在body_html中
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))
        # 把Markdown文本转换成HTML，clean()函数删除所有不在白名单中的标签，linkify()函数把纯文本中的URL转换成适当的 <a> 链接

    def to_json(self):
        json_post = {
            'url': url_for('api.get_post', id=self.id, _external=True),
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp,
            'author': url_for('api.get_user', id=self.author_id,
                              _external=True),
            'comments': url_for('api.get_post_comments', id=self.id,
                                _external=True),
            'comment_count': self.comments.count()
        }
        return json_post

    @staticmethod
    def from_json(json_post):
        body = json_post.get('body')
        if body is None or body == '':
            raise ValidationError('post does not have a body')
        return Post(body=body)


db.event.listen(Post.body, 'set', Post.on_changed_body)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
                        'strong']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

    def to_json(self):
        json_comment = {
            'url': url_for('api.get_comment', id=self.id, _external=True),
            'post': url_for('api.get_post', id=self.post_id, _external=True),
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp,
            'author': url_for('api.get_user', id=self.author_id,
                              _external=True),
        }
        return json_comment

    @staticmethod
    def from_json(json_comment):
        body = json_comment.get('body')
        if body is None or body == '':
            raise ValidationError('comment does not have a body')
        return Comment(body=body)


db.event.listen(Comment.body, 'set', Comment.on_changed_body)
