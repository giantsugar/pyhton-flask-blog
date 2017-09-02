from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


# 登录表单
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    # WTForms 提供的 Length() 和 Email() 验证函数
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('保持登陆')
    # BooleanField 类表示复选框
    submit = SubmitField('登陆')


# 用户注册表单
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    #  WTForms提供的Regexp验证函数，确保username字段只包含字母 数字 下划线和点号
    # 正则表达式后面的两个参数分别是正则表达式的旗标和验 证失败时显示的错误消息
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match.')])
    # WTForms提供的EqualTo验证函数 验证两个密码字段中的值是否一致
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('注册')

    # 为email和username字段定义了验证函数，确保填写的值在数据库中没出现过
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该电子邮箱已经被注册.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名已经在使用.')


# 修改密码表单
class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old password', validators=[Required()])
    password = PasswordField('New password', validators=[
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm new password', validators=[Required()])
    submit = SubmitField('更新密码')


# 定义填写辅助找回密码的电子邮件地址的表格
class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField('重置密码')


# 定义填写新密码的表格
class PasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('New Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('重置密码')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('未知的电子邮箱地址.')


# 更改邮箱的表格
class ChangeEmailForm(FlaskForm):
    email = StringField('New Email', validators=[Required(), Length(1, 64),
                                                 Email()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('更新电子邮箱地址')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该电子邮箱已经被注册.')
