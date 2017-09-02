from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, \
    current_user
from . import auth
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, \
    PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        # 如果当前用户是已经授权的，那么就调用ping方法来刷新last_seen属性
        if not current_user.confirmed \
                and request.endpoint \
                and request.endpoint[:5] != 'auth.' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        # 以上两个中其中一个是True就执行
        # 用户是普通用户必须返回False
        # 所以只能是现在用户已经确认返回True，才能执行跳转到首页
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')
    # 否则跳转到unconfirmed.html页面


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('无效的用户名或密码.')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已经登出.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        # user方法产生用户加密签名token
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        # 发送带有token加密签名的链接的邮件
        flash('确认邮件已经发送到您的邮箱.')
        # 显示flash消息
        return redirect(url_for('auth.login'))
        # 跳转到登录网页
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
# 点击邮件中的链接的路由
@login_required
def confirm(token):
    # Flask-login提供的login_required修饰器会保护这个路由
    # 因此，用户点击这个链接后，要先登录。然后才能执行这个视图函数
    if current_user.confirmed:
        return redirect(url_for('main.index'))
        # 如果现在这个user的属性confirmed是True，证明已经确认了，直接重定向到首页
    if current_user.confirm(token):
        flash('您已经确认了您的账户. 谢谢!')
        # 如果执行了这个函数，更改了confirmed的属性，函数返回了一个True
    else:
        flash('确认链接无效或已经过期.')
        # 如果这个函数返回的是False，显示flash消息
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    # 产生加密签名token
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    # 重新发送带token链接的邮件
    flash('一封新的确认电子邮件已经发到了您的邮箱中.')
    return redirect(url_for('main.index'))
    # 重定向执行main蓝本中index函数


# 更改密码路由
@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
# 要求已经登录
def change_password():
    form = ChangePasswordForm()
    # 创建form实例
    if form.validate_on_submit():
        # 如果表格不为空，执行下列语句
        if current_user.verify_password(form.old_password.data):
            # 如果现在的用户旧密码验证正确，执行下列语句
            current_user.password = form.password.data
            # 表格中的密码赋值给用户中的密码
            db.session.add(current_user)
            # 加入数据库会话，自动提交到数据库
            flash('您的密码已经更新.')
            return redirect(url_for('main.index'))
        else:
            flash('无效的密码.')
            # 否则显示flash消息显示旧密码不对
    return render_template("auth/change_password.html", form=form)
    # 表格为空直接刷新页面


# 点击登录时的忘记密码，进入/rest视图函数
@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        # 如果现在的用户已经登录，已经是普通用户
        return redirect(url_for('main.index'))
        # 直接重定向到主页
    form = PasswordResetRequestForm()
    # 建立表格实例
    if form.validate_on_submit():
        # 如果表格不为空，否则直接出现空表格网页
        user = User.query.filter_by(email=form.email.data).first()
        # 从数据库中筛选出email为表格填写的email的用户
        if user:
            token = user.generate_reset_token()
            # 产生加密签名
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password',
                       user=user, token=token,
                       next=request.args.get('next'))
            # 发送带有token链接的电子邮件，如果成功验证，重定向到之前访问的网页
        flash('有一封重置您的密码的确认邮件已经 '
              '发送给您.')
        return redirect(url_for('auth.login'))
        # 重定向的蓝本中的登录函数，就是显示登录网页
    return render_template('auth/reset_password.html', form=form)


# 点击邮件中的链接，经由这个路由处理
@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    # 建立填写密码的表格实例
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('您的密码已经更新.')
            return redirect(url_for('auth.login'))
            # 如果能执行重置密码的函数，则显示flash消息，重定向到登录页面
        else:
            return redirect(url_for('main.index'))
            # 否则重定向到主页
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_email_change_token(new_email)
            send_email(new_email, 'Confirm your email address',
                       'auth/email/change_email',
                       user=current_user, token=token)
            flash('一封确认您的新的电子邮箱地址的邮件已经 '
                  '发送给您.')
            return redirect(url_for('main.index'))
        else:
            flash('无效的邮箱名或密码.')
    return render_template("auth/change_email.html", form=form)


@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        flash('您的邮箱地址已经更新.')
    else:
        flash('无效的请求.')
    return redirect(url_for('main.index'))
