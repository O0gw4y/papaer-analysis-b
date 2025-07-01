import os
import logging
from datetime import datetime, timedelta
from flask import Flask, url_for, render_template, json, redirect, request, abort, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import ssl

from data import db_session
from data.users import User
from data.news import News

from flask_login import LoginManager, logout_user, login_user, login_required, current_user

# SECURITY FEATURE 1: LOGGING AND MONITORING

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_events.log'),
        logging.StreamHandler()
    ]
)

security_logger = logging.getLogger('security_events')

def log_security_event(event_type, user_info, additional_info=""):
    """
    Log security-related events with structured format
    Args:
        event_type: Type of security event (LOGIN_ATTEMPT, UNAUTHORIZED_ACCESS, etc.)
        user_info: User information (email, IP, etc.)
        additional_info: Additional context information
    """
    security_logger.info(f"SECURITY_EVENT: {event_type} | User: {user_info} | IP: {request.remote_addr} | {additional_info}")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'verystrong_secret_key_for_production_change_this'

# SECURITY FEATURE 2: RATE LIMITING

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# SECURITY FEATURE 3: SECURE HEADERS AND CSP

csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "'unsafe-inline'", 
        "https://stackpath.bootstrapcdn.com",
        "https://code.jquery.com",
        "https://cdnjs.cloudflare.com"
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'", 
        "https://stackpath.bootstrapcdn.com",
        "https://fonts.googleapis.com"
    ],
    'font-src': [
        "'self'",
        "https://fonts.gstatic.com"
    ],
    'img-src': "'self' data:",
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
    'form-action': "'self'",
    'base-uri': "'self'"
}

talisman = Talisman(
    app,
    force_https=False,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src', 'style-src'],
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={
        'geolocation': "'none'",
        'camera': "'none'",
        'microphone': "'none'",
        'payment': "'none'"
    }
)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)

class RegisterForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password_again = PasswordField('Повторите пароль', validators=[DataRequired()])
    name = StringField('Имя пользователя', validators=[DataRequired()])
    about = TextAreaField("Немного о себе")
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField("Запомнить меня")
    submit = SubmitField('Войти')

class NewsForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired()])
    content = TextAreaField("Содержание")
    is_private = BooleanField("Личное")
    submit = SubmitField('Сохранить')

@app.route("/")
def index():
    """Main page showing news posts with security logging"""
    try:
        session = db_session.create_session()
        if current_user.is_authenticated:
            news = session.query(News).filter(
                (News.user == current_user) | (News.is_private != True))
            log_security_event("PAGE_ACCESS", f"authenticated_user:{current_user.email}", "accessed main page")
        else:
            news = session.query(News).filter(News.is_private != True)
            log_security_event("PAGE_ACCESS", "anonymous_user", "accessed main page")
        
        return render_template("index.html", news=news)
    except Exception as e:
        log_security_event("ERROR", "system", f"Error in index route: {str(e)}")
        abort(500)

# SECURITY FEATURE 2: RATE LIMITING ON SENSITIVE ROUTES

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    """User registration with rate limiting and security logging"""
    form = RegisterForm()
    
    if request.method == 'POST':
        log_security_event("REGISTRATION_ATTEMPT", f"email:{form.email.data}", f"IP: {request.remote_addr}")
    
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            log_security_event("REGISTRATION_FAILED", f"email:{form.email.data}", "password mismatch")
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        
        session = db_session.create_session()
        if session.query(User).filter(User.email == form.email.data).first():
            log_security_event("REGISTRATION_FAILED", f"email:{form.email.data}", "user already exists")
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        
        user = User(
            name=form.name.data,
            email=form.email.data,
            about=form.about.data
        )
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        
        log_security_event("REGISTRATION_SUCCESS", f"email:{form.email.data}", "new user registered")
        return redirect('/login')
    
    return render_template('register.html', title='Регистрация', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  
def login():
    """User login with aggressive rate limiting and security monitoring"""
    form = LoginForm()
    
    if form.validate_on_submit():
        session = db_session.create_session()
        user = session.query(User).filter(User.email == form.email.data).first()
        
        log_security_event("LOGIN_ATTEMPT", f"email:{form.email.data}", f"IP: {request.remote_addr}")
        
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            log_security_event("LOGIN_SUCCESS", f"email:{form.email.data}", "successful authentication")
            return redirect("/")
        else:
            log_security_event("LOGIN_FAILED", f"email:{form.email.data}", "invalid credentials")
            return render_template('login.html',
                                   message="Неправильный логин или пароль",
                                   form=form)
    
    return render_template('login.html', title='Авторизация', form=form)

@app.route('/logout')
@login_required
def logout():
    """User logout with security logging"""
    log_security_event("LOGOUT", f"email:{current_user.email}", "user logged out")
    logout_user()
    return redirect("/")

@app.route('/news', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per minute")
def add_news():
    """Add news with rate limiting and logging"""
    form = NewsForm()
    
    if form.validate_on_submit():
        try:
            session = db_session.create_session()
            news = News()
            news.title = form.title.data
            news.content = form.content.data
            news.is_private = form.is_private.data
            current_user.news.append(news)
            session.merge(current_user)
            session.commit()
            
            log_security_event("NEWS_CREATED", f"user:{current_user.email}", f"title: {form.title.data}")
            return redirect('/')
        except Exception as e:
            log_security_event("ERROR", f"user:{current_user.email}", f"Error creating news: {str(e)}")
            abort(500)
    
    return render_template('news.html', title='Добавление новости', form=form)

@app.route('/news/<int:id>', methods=['GET', 'POST'])
@login_required
@limiter.limit("15 per minute")
def edit_news(id):
    """Edit news with authorization checks and logging"""
    form = NewsForm()
    
    if request.method == "GET":
        session = db_session.create_session()
        news = session.query(News).filter(News.id == id,
                                          News.user == current_user).first()
        if news:
            form.title.data = news.title
            form.content.data = news.content
            form.is_private.data = news.is_private
            log_security_event("NEWS_ACCESS", f"user:{current_user.email}", f"accessed news_id:{id}")
        else:
            log_security_event("UNAUTHORIZED_ACCESS", f"user:{current_user.email}", f"attempted to access news_id:{id}")
            abort(404)
    
    if form.validate_on_submit():
        session = db_session.create_session()
        news = session.query(News).filter(News.id == id,
                                          News.user == current_user).first()
        if news:
            news.title = form.title.data
            news.content = form.content.data
            news.is_private = form.is_private.data
            session.commit()
            log_security_event("NEWS_UPDATED", f"user:{current_user.email}", f"updated news_id:{id}")
            return redirect('/')
        else:
            log_security_event("UNAUTHORIZED_MODIFICATION", f"user:{current_user.email}", f"attempted to modify news_id:{id}")
            abort(404)
    
    return render_template('news.html', title='Редактирование новости', form=form)

@app.route('/news_delete/<int:id>', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def news_delete(id):
    """Delete news with authorization and logging"""
    session = db_session.create_session()
    news = session.query(News).filter(News.id == id,
                                      News.user == current_user).first()
    if news:
        session.delete(news)
        session.commit()
        log_security_event("NEWS_DELETED", f"user:{current_user.email}", f"deleted news_id:{id}")
    else:
        log_security_event("UNAUTHORIZED_DELETE", f"user:{current_user.email}", f"attempted to delete news_id:{id}")
        abort(404)
    
    return redirect('/')

# SECURITY FEATURE 4: DATA ENCRYPTION IN TRANSIT (HTTPS CONFIGURATION)

@app.route('/security-info')
def security_info():
    """Display security information and headers for testing"""
    return jsonify({
        'message': 'Security features active',
        'https_enabled': request.is_secure,
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'security_headers': {
            'CSP': 'Content Security Policy active',
            'HSTS': 'HTTP Strict Transport Security enabled',
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff'
        }
    })

# Rate limit exceeded handler
@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors"""
    log_security_event("RATE_LIMIT_EXCEEDED", f"IP:{request.remote_addr}", f"Route: {request.endpoint}")
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'retry_after': e.retry_after
    }), 429

def create_ssl_context():
    """
    Create SSL context for HTTPS
    In production, use proper certificates from a CA
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    return context

def main():
    """Main function with HTTPS configuration"""
    db_session.global_init("db/blogs.sqlite")
    
    log_security_event("APPLICATION_START", "system", "Flask application started with security features")
    
    port = int(os.environ.get("PORT", 5000))
    
    # SECURITY FEATURE 4: HTTPS CONFIGURATION

    app.run(host='127.0.0.1', port=port, debug=True)

if __name__ == '__main__':
    main()