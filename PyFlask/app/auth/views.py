from flask import render_template, redirect, request, url_for, flash
from datetime import datetime
from flask_login import login_user, logout_user, login_required
from . import auth
from ..models import User
from .forms import LoginForm, RegistrationForm, ChangePassword, ChangeEmail
from .. import db
from ..Email import send_mail
from flask_login import current_user


@auth.route('/')
def test():
    return render_template('base.html', current_time=datetime.utcnow())


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verity_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid Email or password')
    return render_template('auth/login.html', form=form, current_time=datetime.utcnow())


@auth.route('/changePwd', methods=['GET', 'POST'])
@login_required
def change_pwd():
    form = ChangePassword()
    if form.validate_on_submit():
        if current_user.verity_password(form.old_password.data):
            current_user.password = form.password.data
            flash('Password modification succeeded')
            return redirect(url_for('main.index'))
        flash('Original password error')
    return render_template('auth/changePwd.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
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
        send_mail(
            user.email, 'Confirm Your Account', 'auth/email/confirm', user=user, token=token
        )
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('you have confirmed your account. thanks!')
    else:
        flash('the confirmation link is invalid or has expired.')
        return render_template('auth/unconfirmed.html')
    return redirect(url_for('main.index'))


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed\
            and request.endpoint[:5] != 'auth.' \
            and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/reconfirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_mail(current_user.email, 'Confirm your Account',
              'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email')
    return redirect(url_for('main.index'))


@auth.route('/changeEmail', methods=['GET', 'POST'])
@login_required
def change_email():
    form = ChangeEmail()
    if form.validate_on_submit():
        if current_user.verity_password(form.password.data):
            email = form.email.data
            token = current_user.generate_confirmation_token(email=email)
            send_mail(
                email, 'Confirm to modify your account', 'auth/email/comfirm_email', user=current_user, token=token
            )
            flash('A confirmation email has been sent to you by email.')
        else:
            flash('Password error')
        return redirect(url_for('main.index'))
    return render_template('auth/changeEmail.html', form=form)


@auth.route('/confirm_email/<token>')
@login_required
def confirm_email(token):
    if current_user.confirm_email(token):
        flash('Verification success!')
    else:
        flash('Verification failure!')
    return redirect(url_for('main.index'))

