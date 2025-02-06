from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from waitress import serve
import os
import uuid

# Инициализация Flask приложения
app = Flask(__name__)
app.config['SECRET_KEY'] = uuid.uuid4().hex
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 * 1024
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///storage.db'  # База данных SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

# Инициализация SQLAlchemy и Flask-Login
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

login_manager.login_message = "Пожалуйста, войдите в аккаунт, чтобы получить доступ к этой странице."
login_manager.login_message_category = "info"
login_manager.needs_refresh_message = "Для продолжения работы необходимо обновить сессию."
login_manager.needs_refresh_message_category = "warning"


# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    folders = db.relationship('Folder', backref='user', lazy=True)  # Связь с папками
    files = db.relationship('File', backref='user', lazy=True)  # Связь с файлами


# Модель папки
class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Связь с пользователем
    files = db.relationship('File', backref='folder', lazy=True)  # Связь с файлами


# Модель файла
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    path = db.Column(db.String(300), nullable=False)  # Путь к файлу на сервере
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Связь с пользователем
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'))  # Связь с папкой (необязательно)


# Загрузка пользователя по ID (требуется для Flask-Login)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Главная страница
@app.route('/')
def index():
    return render_template('index.html')


# Страница "Мои файлы"
@app.route('/my_files')
@login_required
def my_files():
    folders = Folder.query.filter_by(user_id=current_user.id).all()
    files = File.query.filter_by(user_id=current_user.id, folder_id=None).all()  # Файлы вне папок
    return render_template('my_files.html', folders=folders, files=files)


# Страница загрузки файлов
@app.route('/upload_files', methods=['GET', 'POST'])
@login_required
def upload_files():
    if request.method == 'POST':
        file = request.files['file']
        folder_id = request.form.get('folder_id')

        if file:
            user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
            if not os.path.exists(user_upload_dir):
                os.makedirs(user_upload_dir)

            original_filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{original_filename}"
            file_path = os.path.join(user_upload_dir, unique_filename)

            existing_file = File.query.filter_by(name=original_filename, user_id=current_user.id).first()
            if existing_file:
                flash(f'Файл "{original_filename}" уже существует!', 'danger')
                return redirect(url_for('upload_files'))

            file.save(file_path)

            new_file = File(
                name=original_filename,
                path=file_path,
                user_id=current_user.id,
                folder_id=int(folder_id) if folder_id else None
            )
            db.session.add(new_file)
            db.session.commit()

            flash(f'Файл "{original_filename}" успешно загружен!', 'success')
            return redirect(url_for('my_files'))

    folders = Folder.query.filter_by(user_id=current_user.id).all()
    return render_template('upload_files.html', folders=folders)


# Страница создания папки
@app.route('/create_folder', methods=['GET', 'POST'])
@login_required
def create_folder():
    if request.method == 'POST':
        folder_name = request.form.get('folder_name')

        if folder_name:
            new_folder = Folder(name=folder_name, user_id=current_user.id)
            db.session.add(new_folder)
            db.session.commit()

            flash(f'Папка "{folder_name}" успешно создана!', 'success')
            return redirect(url_for('my_files'))
    return render_template('create_folder.html')


# Просмотр содержимого папки
@app.route('/view_folder/<int:folder_id>')
@login_required
def view_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    if folder.user_id != current_user.id:
        flash('У вас нет доступа к этой папке.', 'danger')
        return redirect(url_for('my_files'))

    files = File.query.filter_by(folder_id=folder_id).all()
    return render_template('view_folder.html', folder=folder, files=files)


# Удаление папки
@app.route('/delete_folder/<int:folder_id>')
@login_required
def delete_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    if folder.user_id != current_user.id:
        flash('У вас нет доступа к этой папке.', 'danger')
        return redirect(url_for('my_files'))

    db.session.delete(folder)
    db.session.commit()
    flash(f'Папка "{folder.name}" успешно удалена!', 'success')
    return redirect(url_for('my_files'))


# Удаление файла
@app.route('/delete_file/<int:file_id>')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash('У вас нет доступа к этому файлу.', 'danger')
        return redirect(url_for('my_files'))

    if os.path.exists(file.path):
        os.remove(file.path)

    db.session.delete(file)
    db.session.commit()
    flash(f'Файл "{file.name}" успешно удален!', 'success')
    return redirect(url_for('my_files'))


# Скачивание файла
@app.route('/download_file/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash('У вас нет доступа к этому файлу.', 'danger')
        return redirect(url_for('my_files'))

    return send_from_directory(
        os.path.dirname(file.path),
        os.path.basename(file.path),
        as_attachment=True,
        download_name=file.name
    )


# Страница входа в аккаунт
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Вы успешно вошли в аккаунт!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль.', 'danger')
    return render_template('login.html')


# Выход из аккаунта
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из аккаунта.', 'info')
    return redirect(url_for('index'))


# Страница регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash('Заполните все поля.', 'danger')
        elif password != confirm_password:
            flash('Пароли не совпадают.', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Имя пользователя уже занято.', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Аккаунт успешно создан! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # Debug/Development
    # app.run(debug=True, host="0.0.0.0", port="5000")
    # Production
    serve(app, host="0.0.0.0", port=5000)
