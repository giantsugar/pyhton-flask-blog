from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, SelectField, \
    SubmitField
from wtforms.validators import Required, Length, Email, Regexp
from wtforms import ValidationError
from ..models import Role, User
from flask_pagedown.fields import PageDownField


# 博客文章表单
class PostForm(FlaskForm):
    body = PageDownField("您想发布什么?", validators=[Required()])
    submit = SubmitField('提交')


# 资料编辑表单
class EditProfileForm(FlaskForm):
    name = StringField('真实姓名', validators=[Length(0, 64)])
    # 这里Length设置(0,64)的意思是可选项，不一定必填
    location = StringField('所在地', validators=[Length(0, 64)])
    about_me = TextAreaField('关于我')
    # TextAreaField，一个文本框功能
    submit = SubmitField('提交')


# 管理员使用的资料编辑表单
class EditProfileAdminForm(FlaskForm):
    email = StringField('邮箱', validators=[Required(), Length(1, 64),
                                             Email()])
    username = StringField('用户名', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    # wtf对HTML表单控件 <select> 进行SelectField包装，从而实现下拉列表
    name = StringField('真实姓名', validators=[Length(0, 64)])
    location = StringField('所在地', validators=[Length(0, 64)])
    about_me = TextAreaField('关于我')
    submit = SubmitField('提交')

    def __init__(self, user, *args, **kwargs):
        # 在生成表单的时候，是需要带着参数user的
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        # role.choices属性，是针对的表单role的选项
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
                # 检验email是否发生更改且是否重复
            raise ValidationError('该邮箱已经被注册.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
                # 检验username是否发生更改且是否重复
            raise ValidationError('用户名已经在使用.')


# 评论输入表单
class CommentForm(FlaskForm):
    body = StringField('', validators=[Required()])
    submit = SubmitField('提交')
