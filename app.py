from flask import Flask,render_template,request,redirect, url_for,session,flash,abort,Response,jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey, CheckConstraint, Enum
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
import re
from functools import wraps
from sqlalchemy import or_
import logging
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_paginate import Pagination, get_page_parameter,get_page_args

from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin.contrib.sqla import ModelView
from werkzeug.exceptions import BadRequest
from models import db, User, Book, BorrowBook, BorrowHistory, Admin

import requests

from dotenv import load_dotenv
import os
load_dotenv()


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

app.secret_key = os.getenv('SECRET_KEY')
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')
DEFAULT_IMAGE = os.getenv('DEFAULT_IMAGE')


login_manager = LoginManager(app)
login_manager.login_view = 'login'




@app.route('/proxy')
def proxy():
    # クライアントからのリクエストで指定された画像URLを取得
    image_url = request.args.get('url')
    
    # 外部の画像URLにリクエストを送信
    response = requests.get(image_url, stream=True)

    # レスポンスのコンテンツタイプを取得
    content_type = response.headers.get('content-type')

    # レスポンスをストリームで直接クライアントに送信
    return Response(response.iter_content(chunk_size=1024), content_type=content_type)




@login_manager.user_loader
def load_user(id):
    if 'user_type' in session:
        if session['user_type'] == 'admin':
            return Admin.query.get(int(id))
    return User.query.get(int(id))

    
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    try:  
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')

            if not email or not password:
                flash('Eメールとパスワードを入力してください。', 'warning')
                return redirect(url_for('login'))

            # データベースからユーザーを取得
            user = None
            try:
                user = User.query.filter_by(email=email).first()
                
                if user:
                    if user.is_locked():
                        flash('このアカウントはロックされています。', 'danger')
                        return redirect(url_for('login'))
                    if user.password == password:
                        login_user(user)
                        session['user_type'] = 'user'
                        user.failed_login_attempts = 0
                        return redirect(url_for('user_dashboard'))
                    else:
                        user.failed_login_attempts += 1
                        if user.failed_login_attempts >= 3:
                            user.locked_until = datetime.utcnow() +timedelta(minutes=15)
                        db.session.commit()
                        flash('無効なパスワード。', 'danger')
                        return redirect(url_for('login'))
                else:
                    flash('ユーザー名は存在しません。','danger')
            except Exception as e:
                print(f"データベースエラー: {e}")
                flash('システムエラーが発生しました。しばらくしてから再度お試しください。', 'danger')
                return redirect(url_for('login'))
        return render_template('login.html')
    except Exception as e:
        print(f"予期しないエラー: {e}")
        flash('予期しないエラーが発生しました。', 'danger')
        return render_template('login.html')



@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            admin = Admin.query.filter_by(email=email).first()
            # check_password_hash(staff.password, password)
            if admin:
                if admin.password == password:
                    login_user(admin)
                    session['user_type'] = 'admin'
                    return redirect(url_for('admin_dashboard'))
        except Exception as e:
            print(f"ログイン時のエラー: {e}")
            
            flash('ログインに失敗しました。ユーザー名とパスワードを確認してください。', 'danger')
        
    return render_template('admin_login.html')    
        
def is_valid_email(email):
    return re.match(r'[^@]+@[^@]+\.[^@]+', email)        
        
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if User.query.filter_by(email=email).first():
            flash('Eメールはすでに存在している。', 'danger')
            return redirect(url_for('register'))

    # 入力値のチェック
    if not (name and email and password):
        flash('全て必須項目です。 フォームにご記入ください', 'danger')
        return render_template('register.html')


    if not is_valid_email(email):
        flash('メールアドレスが無効です！', 'danger')
        return render_template('register.html')
    
    
    # hashed_password = generate_password_hash(password, method='sha256')
    try:
        # 新しいユーザーを追加
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    except Exception as e:
        print(f"登録時のエラー: {e}")
        flash('登録中にエラーが発生しました。再度お試しください。', 'danger')
        return render_template('register.html')
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))




def user_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if 'user_type' not in session or session['user_type'] != 'user':
            flash('このページは一般ユーザーのみアクセス可能です。', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if 'user_type' not in session or session['user_type'] != 'admin':
            flash('このページはスタッフのみアクセス可能です。', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function





        




@app.route('/admin_dashboard',methods=['GET','POST'] )
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')
    

@app.route('/user_dashboard',methods=['GET','POST'] )
@user_required
def user_dashboard():
    return render_template('user_dashboard.html')
    
    
    
@app.route("/books", methods=['GET', 'POST'])
@admin_required
def books():
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page', per_page=5)
    total = Book.query.count()
    books = Book.query.order_by(Book.bookid.desc()).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template("books.html", books=books, pagination=pagination)
    
    
@app.route("/user_books", methods=['GET','POST'])
@user_required
def user_books():
    page, per_page, offset = get_page_args(page_parameter='page',per_page_parameter='per_page',per_page=5)
    total = Book.query.count()
    books = Book.query.order_by(Book.bookid.desc()).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')
    return render_template("user_books.html", books=books, pagination=pagination)
    
    



# @app.route('/search_books', methods=['GET'])
# def search_books():
#     query = request.args.get('q')
#     if not query:
#         return redirect(url_for('books'))
#     books = Book.query.filter(Book.name.like(f'%{query}%')).all()
#     return render_template('book_search_result.html',books=books)

@app.route('/search_books', methods=['GET'])
def search_books():
    query = request.args.get('q')
    if not query:
        return redirect(url_for('books'))

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page', per_page=5)
    total = Book.query.filter(Book.name.like(f'%{query}%')).count()
    books = Book.query.filter(Book.name.like(f'%{query}%')).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, record_name='books', css_framework='bootstrap4')

    return render_template('book_search_result.html', books=books, pagination=pagination,query=query)

@app.route('/user_search_books', methods=['GET'])
def user_search_books():
    query = request.args.get('q')
    if not query:
        return redirect(url_for('user_books'))
    
    

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page', per_page=5)
    total = Book.query.filter(Book.name.like(f'%{query}%')).count()
    books = Book.query.filter(Book.name.like(f'%{query}%')).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, record_name='books', css_framework='bootstrap4')

    return render_template('user_book_search_result.html', books=books, pagination=pagination,query=query)
        


def allowed_file(filename):
    ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])  # ここに許可したい拡張子を追加/削除できます
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_image():
    picture = ''
    # if 'picture' in request.files and request.files['picture'].filename:
    #     raise BadRequest("画像がアップロードされていません")
    
    if 'picture' not in request.files or not request.files['picture'].filename:
        return DEFAULT_IMAGE

    file = request.files['picture']
    filename = secure_filename(file.filename)
    
    if not filename or not allowed_file(filename):
        print(filename)
        raise BadRequest("無効なファイル名ですまたは許可されていないファイル形式です")
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    
    try:
        file.save(file_path)
        picture = filename
        
    except Exception as e:
        raise BadRequest(f"画像のアップロード中にエラーが発生しました: {e}")
    
    return picture

def get_book_or_404(bookid):
    book = Book.query.filter(Book.bookid == bookid).one_or_none()
    if not book:
        abort(404, "本が見つかりません")
    return book


def get_book_from_rakuten(isbn):
    RAKUTEN_API_URL = "https://app.rakuten.co.jp/services/api/BooksTotal/Search/20170404"
    RAKUTEN_API_KEY = "1076988849503284276"  # Replace with your Rakuten API Key
    params = {
        "isbnjan": isbn,
        "applicationId": RAKUTEN_API_KEY,
        "format": "json"
    }
    
    response = requests.get(RAKUTEN_API_URL, params=params)
    data = response.json()
    
    if "Items" in data and data["Items"]:
        book_item = data["Items"][0].get("Item", {})
        return {
            "title": book_item.get("title", "N/A"),
            "author": book_item.get("author", "N/A"),
            "publisher": book_item.get("publisherName", "N/A"),
            "release_date": book_item.get("salesDate", "N/A"),
            "image_url": book_item.get("largeImageUrl", "N/A"),
            "summary": book_item.get("itemCaption", "情報なし")
        }
    return None

    
@app.route('/book_add', methods=['GET','POST'])
@admin_required
def book_add():
    if request.method == 'POST':
        if 'isbn_search' in request.form:
            isbn = request.form.get('isbn')
            book_isbn = get_book_from_rakuten(isbn)
            print(book_isbn)
            if book_isbn:
                return render_template('book_add_form.html', book_isbn=book_isbn)
            else:
                flash('検索の結果なかった。')
                return redirect(url_for('book_add'))
        elif 'book_submit' in request.form:
            try:
                picture = upload_image()
            except Exception as e:
                flash(f"画像のアップロード中にエラーが発生しました: {str(e)}", "error")
                return redirect(url_for('book_add'))
            name = request.form.get('name')
            author = request.form.get('author')
            publisher = request.form.get('publisher')
            release_date = request.form.get('release_date')
            detail = request.form.get('detail')
            
            
            if not name or not detail:
                flash("必要な情報が入力されていません。", "error")
                return redirect(url_for('book_add'))
            
            new_book = Book(picture=picture,name=name,author=author,publisher=publisher,release_date=release_date,detail=detail)
            
            db.session.add(new_book)
            db.session.commit()
            return redirect('books')
    return render_template('book_add_form.html')







@app.route('/book_detail/<int:bookid>',methods=['GET','POST'])
@admin_required
def book_detail(bookid):
    book = get_book_or_404(bookid)
    return render_template('book_detail.html', book=book)
    
@app.route('/user_book_detail/<int:bookid>',methods=['GET','POST'])
@user_required
def user_book_detail(bookid):
    book = get_book_or_404(bookid)
    return render_template('user_book_detail.html', book=book)
    
    
@app.route('/book_update/<int:bookid>',methods=['GET','POST'])
@login_required
def book_update(bookid):
    
    book = get_book_or_404(bookid)

    if request.method == 'POST':
        book.picture = upload_image()
        book.name = request.form.get('name')
        book.detail = request.form.get('detail')
        book.author = request.form.get('author')
        book.publisher = request.form.get('publisher')
        book.release_date = request.form.get('release_date')
            

        db.session.commit()
        flash('編集成功！！！')
        return redirect(url_for('books'))
    return render_template('book_update_form.html', book=book)

    
@app.route('/book_delete/<int:bookid>', methods=['GET','POST'])
@admin_required
def book_delete(bookid):
    book = get_book_or_404(bookid)
    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('books')) 
    
    
@app.route('/admin',methods=['GET', 'POST'])    
@admin_required
def admin():
    admins = Admin.query.all()
    return render_template('admin_screen.html',admins=admins)


@app.route('/admin_add',methods=['GET', 'POST'])
@admin_required
def admin_add():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        # action = request.form.get('staff_add')
        
        if not is_valid_email(email):
            flash('メールアドレスが無効です！', 'danger')
            return render_template('register.html')
        
        new_staff = Admin(
            username = name,
            email = email,
            password = password
        )
            
        
                
        db.session.add(new_staff)
        db.session.commit()
        
        return redirect(url_for('admin'))
        
            
        
    return render_template('admin_add.html')
    
        
@app.route('/admin_edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit(id):
    admin = Admin.query.filter(Admin.id==id).one_or_none()
    if request.method == 'POST':
        admin.username = request.form.get('name')
        admin.email = request.form.get('email')
        admin.password = request.form.get('password')
        
        db.session.commit()
        return redirect(url_for('admin'))
    return render_template('admin_edit.html',admin=admin)    


@app.route('/admin_delete/<int:id>',methods=['GET', 'POST'])
@admin_required
def admin_delete(id):
    staff = Admin.query.filter(Admin.id==id).one_or_none()
    db.session.delete(staff)
    db.session.commit()
    return redirect(url_for('admin'))
    
    
@app.route('/user', methods=['GET','POST'])      
@admin_required
def user():
    users = User.query.all()
    return render_template('user_list.html',users=users)
        
        
@app.route('/unlock/<int:id>')
@admin_required
def unlock_user(id):
    if session['user_type'] == 'admin':
        user = User.query.get(id)
        if user:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()
            flash('ユーザーは正常にロックを解除しました。', 'success')
            return redirect(url_for('user'))
        else:
            flash('ユーザーが見つかりません。', 'danger')
    else:
        flash('許可が拒否されました。', 'danger')
    return redirect(url_for('user'))




@app.route('/loan_return_history', methods=['GET','POST'])
def loan_return_history():
    book_historys = BorrowHistory.query.all()
    return render_template('loan_return_history.html',book_historys=book_historys)
    











@app.route('/books_borrowed', methods=['GET','POST'])
@user_required
def books_borrowed():
    books = Book.query.all()

    return render_template("books_borrowed.html", books=books)



@app.route('/book_borrow/<int:id>', methods=['GET','POST'])
@user_required
def book_borrow(id):
    

    user_id = current_user.id
    user = User.query.get(user_id)

    if not user:
        flash("ユーザーが見つかりません！", "error")
        return redirect(url_for('books_borrowed.html'))

    # このユーザーによって借りられた本の数をリレーションシップを利用して取得
    borrowed_books_count = len(user.borrow_books)

    if borrowed_books_count == 1:
        return '借りられる上限を越しました'

    book = Book.query.get(id)
    if not book:
        flash("本が見つかりません！", "error")
        return redirect(url_for('books_borrowed'))

    try:
        issue = BorrowBook(bookid=book.bookid, userid=user_id)
        db.session.add(issue)

        book.status = 'borrowed'
        
        #本を借りた履歴をのこす
        book_history = BorrowHistory(userid=user_id,bookid=book.bookid,borrowed_date=datetime.utcnow())
        
        db.session.add(book_history)
        
        db.session.commit()

        flash(f"借り入れに成功 {book.name}", "success")
        return render_template('book_borrowed_message.html', book=book)

    except Exception as e:
        flash(f"本の貸し出しエラー: {e}", "error")
        return redirect(url_for('books_borrowed'))


@app.route('/book_return_screen', methods=['GET', 'POST'])
@user_required
def book_return_screen():

        
    
    
        user_id = current_user.id
        if not user_id:
            flash("セッションが無効です。再度ログインしてください。", "error")
            return redirect(url_for('login'))

        user = User.query.get(user_id)
        if not user:
            flash("ユーザーが見つかりません！", "error")
            return redirect(url_for('login'))

        # userオブジェクトのborrow_booksリレーションシップを使用して、
        # ユーザーが現在借りているすべての本を直接取得
        if not hasattr(user, 'borrow_books') or not user.borrow_books:
            flash("借りている本はありません。", "info")
            return render_template('book_return_screen.html', return_books=[])

        books_return = [borrow.book for borrow in user.borrow_books]
        
        

        return render_template('book_return_screen.html', books_return=books_return)
    
    

    


@app.route('/book_return/<int:id>', methods=['GET', 'POST'])
@user_required
def book_return(id):
    
    book = Book.query.get(id)

    book_return = BorrowBook.query.filter_by(bookid=id).first()
    

    
    
    
    book_history = BorrowHistory.query.filter_by(bookid=id, returned_date=None).first()
    
    
    if not book_return:
        logging.error(f"貸出履歴が見つからない: Book ID {id}")
        flash(f"該当する本の貸し出し履歴が見つかりません。Book ID: {id}", "error")
        return redirect(url_for('book_return_screen'))

    
    if not book:
        flash("本が見つかりません。", "error")
        return redirect(url_for('book_return_screen'))

    
    if not book_history:
        logging.error(f"ID付き書籍の貸出履歴が見つかりません: {id}")
        
        detailed_message = f"ID 付きの本の借用履歴が見つかりませんでした: id: {id}。 データベースまたは指定された ID を確認してください。"
        flash(detailed_message, "error")

        
        flash("ああ貸し出し履歴が見つかりません。", "error")
        return redirect(url_for('book_return_screen'))

    try:
        # 本の状態の更新
        book.status = 'lending'
        
        # 貸し出し履歴の更新
        # first_history = book_history[0]
        book_history.returned_date = datetime.utcnow()
        # print(f"{book_history.returned_date} これ！！")

        # 借りている本のエントリを削除
        db.session.delete(book_return)

        

        # 変更を確定
        db.session.commit()

    except Exception as e:
        db.session.rollback()  # エラー時には変更をロールバック
        flash(f"返却エラー: {e}", "error")
        return redirect(url_for('book_return_screen'))

    return render_template('book_return_message.html', book_return=book_return)

    
    
    
    
@app.route('/search', methods=['GET', 'POST'])
@user_required
def search():
    if request.method == 'POST':
        search = request.form.get('name')
        
        results = Book.query.filter(
            or_(
                Book.name.contains(search),
                # Book.isbn.contains(search)
            )
        
        ).all()
        
        if not results:
            return '検索結果なし'
        
        return render_template('book_search_results.html', results=results)
    
    return render_template('book_search.html')
        

@app.route('/books_borrowing/<int:id>',methods=['POST','GET'])
@user_required
def books_borrowing(id):
    if current_user.id != id:
        abort(403)
    
    books = BorrowBook.query.filter(BorrowBook.userid == id).all()
    
    return render_template('books_borrowing.html',books=books)
    
# @app.route('/user_books', methods=['POST','GET'])
# @user_required
# def user_books():
#     books = Book.query.all()
#     return render_template("user_books.html", books=books)
    
    
# @app.route("/user_books_list",methods=['GET','POST'])
# @user_required
# def user_books_list():
#     books_list = Book.query.all()
    
#     return jsonify([{'id': book.bookid,'picture': book.picture,'title': book.name, 'detail':book.detail,'author': book.author,'release_date': book.release_date,'publisher': book.publisher or '出版社（不明）','status': book.status} for book in books_list])


# @app.route('/user_search_books', methods=['GET'])
# def user_search_books():
#     query = request.args.get('q')
#     books = Book.query.filter(Book.name.like(f'%{query}%')).all()
#     return jsonify([{'id': book.bookid,'picture': book.picture,'title': book.name, 'detail':book.detail,'author': book.author,'release_date': book.release_date,'publisher': book.publisher or '出版社（不明）','status': book.status} for book in books])


    
    


def seed_data():
    # Clearing existing data:
    # WARNING: This will remove all existing data from the tables!
    User.query.delete()
    Admin.query.delete()

    # Adding Users:
    user = User(name="u", email="u@e.com", password="u")
    # admin = User(name="a", email="a@e.com", password="a", role="admin")
    admin = Admin(username="たける", email="t@e.com" ,password="t")
    
    user2 = User(name='たける',email='t@e.com',password='t')


    # Adding instances to the session:
    db.session.add(user)
    db.session.add(user2)
    # db.session.add(admin)
    db.session.add(admin)

    # Committing the changes:
    db.session.commit()
    
    
    





if __name__ == '__main__':
    
    with app.app_context():
        db.create_all()
        seed_data()
        
    app.run(port='3001',debug=True)