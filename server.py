from flask import Flask, render_template, flash, redirect, url_for, request, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
import os
import requests

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['YANDEX_MAPS_API_KEY'] = '5edfcff0-94a7-4c66-bbc0-f743141f39c6'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    favorites = db.relationship('Favorite', backref='user', lazy=True)


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    coordinates = db.Column(db.String(50), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Имя пользователя уже занято')


class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class SearchForm(FlaskForm):
    query = StringField('Поиск адреса', validators=[DataRequired()])
    show_postcode = BooleanField('Показывать почтовый индекс')
    submit = SubmitField('Искать')
    reset = SubmitField('Сбросить')


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Регистрация успешна!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Неверные данные', 'danger')
    return render_template('login.html', form=form)


@app.route('/delete_favorite/<int:fav_id>', methods=['POST'])
@login_required
def delete_favorite(fav_id):
    fav = Favorite.query.get_or_404(fav_id)
    if fav.user_id != current_user.id:
        abort(403)
    db.session.delete(fav)
    db.session.commit()
    flash('Адрес удален из избранного', 'success')
    return redirect(url_for('dashboard'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = SearchForm()
    map_url = address = postcode = None
    show_postcode = False

    if 'last_search' in session:
        address = session['last_search'].get('address')
        postcode = session['last_search'].get('postcode')
        map_url = session['last_search'].get('map_url')
        show_postcode = session['last_search'].get('show_postcode', False)

    if form.reset.data:
        session.pop('last_search', None)
        return redirect(url_for('dashboard'))

    if form.submit.data and form.validate():
        try:
            geocode_url = "https://geocode-maps.yandex.ru/1.x/"
            params = {
                "apikey": app.config['YANDEX_MAPS_API_KEY'],
                "geocode": form.query.data,
                "format": "json",
                "results": 1
            }
            response = requests.get(geocode_url, params=params)
            response.raise_for_status()
            data = response.json()

            if not data["response"]["GeoObjectCollection"]["featureMember"]:
                flash('Адрес не найден', 'danger')
                return redirect(url_for('dashboard'))

            feature = data["response"]["GeoObjectCollection"]["featureMember"][0]["GeoObject"]
            pos = feature["Point"]["pos"].split()
            lon, lat = pos[0], pos[1]

            address = feature["metaDataProperty"]["GeocoderMetaData"]["text"]
            postcode = feature["metaDataProperty"]["GeocoderMetaData"]["Address"].get("postal_code")

            kind = feature["metaDataProperty"]["GeocoderMetaData"].get("kind", "")
            is_country = "country" in kind.lower()
            zoom = "5" if is_country else "15"

            map_params = {
                "ll": f"{lon},{lat}",
                "z": zoom,
                "l": "map",
                "size": "650,450",
                "pt": f"{lon},{lat},pm2dgl"
            }
            map_url = f"https://static-maps.yandex.ru/1.x/?{'&'.join(f'{k}={v}' for k, v in map_params.items())}"

            session['last_search'] = {
                'address': address,
                'postcode': postcode,
                'map_url': map_url,
                'show_postcode': form.show_postcode.data,
                'coordinates': f"{lon},{lat}"
            }

        except Exception as e:
            flash(f'Ошибка: {str(e)}', 'danger')

    if request.method == 'POST' and 'add_to_favorite' in request.form and 'last_search' in session:
        try:
            existing = Favorite.query.filter_by(
                user_id=current_user.id,
                coordinates=session['last_search']['coordinates']
            ).first()

            if not existing:
                fav = Favorite(
                    user_id=current_user.id,
                    address=session['last_search']['address'],
                    coordinates=session['last_search']['coordinates']
                )
                db.session.add(fav)
                db.session.commit()
                flash('Адрес добавлен в избранное', 'success')
            else:
                flash('Этот адрес уже в избранном', 'info')
        except Exception as e:
            flash(f'Ошибка при добавлении в избранное: {str(e)}', 'danger')

    return render_template(
        'dashboard.html',
        form=form,
        username=current_user.username,
        map_url=map_url,
        address=address,
        postcode=postcode,
        show_postcode=show_postcode,
        favorites=current_user.favorites
    )


@app.route('/favorite/<int:fav_id>')
@login_required
def show_favorite(fav_id):
    fav = Favorite.query.get_or_404(fav_id)
    if fav.user_id != current_user.id:
        abort(403)

    lon, lat = fav.coordinates.split(',')
    is_country = "страна" in fav.address.lower()
    zoom = "5" if is_country else "15"

    map_params = {
        "ll": fav.coordinates,
        "z": zoom,
        "l": "map",
        "size": "650,450",
        "pt": f"{lon},{lat},pm2dgl"
    }
    map_url = f"https://static-maps.yandex.ru/1.x/?{'&'.join(f'{k}={v}' for k, v in map_params.items())}"

    session['last_search'] = {
        'address': fav.address,
        'map_url': map_url,
        'show_postcode': False,
        'coordinates': fav.coordinates
    }

    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=8080, host='127.0.0.1')
